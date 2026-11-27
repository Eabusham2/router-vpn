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
import android.view.ContextThemeWrapper;
import android.view.Gravity;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewGroup;
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
    private RouterVpnNodeMapView mapView; private LinearLayout sheet,primaryControls; private ScrollView sheetScroll;
    private TextView sheetHandle,nodeButton,statusView,modeHint,dnsHint,multihopHint,liveLatency,autoRequirementsHint;
    private Button connectButton,fastestButton,performanceButton,forwardButton,hopsButton;
    private static final String CREATE_CUSTOM_ACTION="action:create-custom";
    private static final String[] DNS_MODES={"home","fastest","custom","dot","doh","doh3","rescue"};
    private int displayedDnsIndex=-1;
    private CheckBox killSwitch,multihopToggle; private Spinner modeSpinner,dnsSpinner; private List<ModeChoice> modeChoices=new ArrayList<>();
    private float sheetTouchY; private boolean sheetExpanded,telemetryBusy,forwardingBusy; private long lastTelemetryAt;
    private String pendingProbeEntryId=""; private ArrayList<String> pendingProbeCandidateIds=new ArrayList<>();
    private long viaEntryGeneration;
    private AlertDialog viaEntryDialog;
    private String importDecision="";
    private long importGeneration,telemetryGeneration;
    private boolean resumed;
    private String fastestCatalogKey="";
    private long fastestCatalogTicket;
    private AlertDialog currentSpeedDialog;
    private AlertDialog fastestProgressDialog;
    private AndroidHopMeasurementDialog routedHopDialog;
    private AndroidOrderedLatencyDialog orderedLatencyDialog;
    private AndroidNodeCandidateDialog candidateDialog;
    private AndroidOrderedCandidatePicker orderedPicker;
    private AndroidNodeCandidatePreparationDialog preparedCandidateDialog;
    private AndroidExternalBenchmarkDialog externalBenchmarkDialog;
    private AndroidExternalComparisonDialog externalComparisonDialog;
    private AndroidTelemetry.PathResult currentPathReceipt;
    private TextView multihopTotal, liveRouteDetails;
    private AlertDialog liveRouteDialog;
    private AndroidExternalLiveTelemetry externalTelemetry;
    private AndroidExternalLiveTelemetry.Result currentExternalReceipt;
    private AndroidOrderedPathPresentation orderedPresentation;
    private boolean orderedPresentationPending;
    private long orderedPresentationGeneration;
    private String externalProtectionID="",externalProtectionSource="";
    private final android.os.Handler telemetryHandler=new android.os.Handler(android.os.Looper.getMainLooper());
    private final Runnable telemetryTick=new Runnable(){public void run(){if(!resumed||isFinishing()||isDestroyed())return;requestOrderedPresentation();refreshTelemetry(false);refreshLiveRoute();telemetryHandler.postDelayed(this,5000);}};

    private static final class ModeChoice {
        final String id, title;
        final List<String> layers;
        final boolean available;
        ModeChoice(String id, String title) { this(id, title, Collections.emptyList()); }
        ModeChoice(String id, String title, List<String> layers) { this(id, title, layers, true); }
        ModeChoice(String id, String title, List<String> layers, boolean available) {
            this.id = id;
            this.title = title;
            this.layers = layers == null ? Collections.emptyList() : layers;
            this.available = available;
        }
        @Override public String toString() { return title; }
    }
    private static final class CustomPreset { String name; List<String> layers; CustomPreset(String name,List<String>layers){this.name=name;this.layers=layers;} }

    @Override protected void onCreate(Bundle state){super.onCreate(state);nodeStore=new AndroidNodeStore(this);exitStore=new AndroidStandardExitStore(this);catalog=new AndroidUnifiedNodeCatalog(nodeStore,exitStore);connection=new AndroidUnifiedConnectionController(this,nodeStore);telemetry=new AndroidTelemetry(this,nodeStore);externalTelemetry=new AndroidExternalLiveTelemetry(this,AndroidRuntimeRegistry.get(this).standardExit);forwardingMaster=new AndroidForwardingMaster(this,nodeStore);viaEntryProbe=new AndroidViaEntryLatencyProbe(this,AndroidRuntimeRegistry.get(this),telemetry);if(state!=null){importDecision=state.getString(STATE_IMPORT_DECISION,"");pendingProbeEntryId=state.getString(STATE_PROBE_ENTRY,"");ArrayList<String> ids=state.getStringArrayList(STATE_PROBE_CANDIDATES);if(ids!=null)pendingProbeCandidateIds=ids;}setContentView(buildUi());refreshAll();if(state!=null&&!AndroidExternalNodeComparison.hasActiveOperation())connection.restorePending(state,callback());applyStartupPolicy(state!=null);AndroidProductOnboarding.showIfNeeded(this);}
    @Override protected void onResume(){super.onResume();resumed=true;if(connection!=null)connection.resumePending();resumeCandidatePreparation();telemetryHandler.removeCallbacks(telemetryTick);telemetryHandler.post(telemetryTick);refreshAll();if(viaEntryProbe!=null&&viaEntryProbe.isBusy()&&!pendingProbeEntryId.isEmpty())statusView.setText("Measuring live via-entry multihop candidate RTT…");}
    @Override protected void onPause(){fastestCatalogTicket++;fastestCatalogKey="";if(orderedPicker!=null)orderedPicker.pause();closeOrderedLatency();closeRoutedHopMeasurement();closeCandidateMeasurement();detachCandidatePreparation();resumed=false;telemetryGeneration++;telemetryHandler.removeCallbacks(telemetryTick);if(externalTelemetry!=null)externalTelemetry.cancel();clearCurrentTelemetry();if(telemetry!=null){telemetry.cancelCurrent();telemetry.cancelFastest();}if(currentSpeedDialog!=null){currentSpeedDialog.dismiss();currentSpeedDialog=null;}if(externalBenchmarkDialog!=null){externalBenchmarkDialog.close();externalBenchmarkDialog=null;}super.onPause();}
    @Override protected void onSaveInstanceState(Bundle out){if(!importDecision.isEmpty())out.putString(STATE_IMPORT_DECISION,importDecision);if(connection!=null)connection.savePending(out);if(viaEntryProbe==null||!viaEntryProbe.isBusy()){if(!pendingProbeEntryId.isEmpty())out.putString(STATE_PROBE_ENTRY,pendingProbeEntryId);if(!pendingProbeCandidateIds.isEmpty())out.putStringArrayList(STATE_PROBE_CANDIDATES,new ArrayList<>(pendingProbeCandidateIds));}super.onSaveInstanceState(out);}
    @Override protected void onDestroy(){closeOrderedPicker();if(liveRouteDialog!=null)liveRouteDialog.dismiss();closeOrderedLatency();closeRoutedHopMeasurement();closeCandidateMeasurement();detachCandidatePreparation();importGeneration++;telemetryGeneration++;telemetryHandler.removeCallbacks(telemetryTick);if(externalTelemetry!=null)externalTelemetry.cancel();if(telemetry!=null)telemetry.close();if(fastestProgressDialog!=null){fastestProgressDialog.dismiss();fastestProgressDialog=null;}if(externalBenchmarkDialog!=null){externalBenchmarkDialog.close();externalBenchmarkDialog=null;}viaEntryGeneration++;if(viaEntryProbe!=null)viaEntryProbe.cancel();if(viaEntryDialog!=null){viaEntryDialog.dismiss();viaEntryDialog=null;}if(externalComparisonDialog!=null){externalComparisonDialog.close();externalComparisonDialog=null;}if(isFinishing())AndroidStartupPolicy.cancelPending();if(connection!=null)connection.close();super.onDestroy();}
    @Override protected void onActivityResult(int requestCode,int resultCode,Intent data){if(AndroidOrderedCandidatePicker.isPermissionRequest(requestCode)){if(orderedPicker!=null)orderedPicker.permission(requestCode,resultCode==RESULT_OK);return;}if(requestCode==IMPORT_ROUTER_BUNDLE){receiveRouterBundle(resultCode,data);return;}if(requestCode==PREPARE_VIA_ENTRY_RTT){if(resultCode==RESULT_OK)runPendingViaEntryProbe();else{AndroidNodeStore.Node entry=quietNode(pendingProbeEntryId);List<AndroidNodeStore.Node> exits=quietNodes(pendingProbeCandidateIds);clearPendingProbe();try{showViaEntryExitPicker(viaEntryProbe.unmeasured(entry,exits),new IllegalStateException("Android VPN permission was not granted; via-entry RTT is unavailable."));}catch(Exception error){toast(safe(error));}}return;}if(connection!=null&&connection.onActivityResult(requestCode,resultCode)){refreshConnectionLater();return;}super.onActivityResult(requestCode,resultCode,data);}

    @Override public void onRequestPermissionsResult(int requestCode,String[] permissions,int[] grantResults){if(AndroidUpdateDialog.onPermissionResult(this,requestCode))return;super.onRequestPermissionsResult(requestCode,permissions,grantResults);}

    private View buildUi(){
        LinearLayout root=new LinearLayout(this){
            @Override protected void onMeasure(int widthSpec,int heightSpec){
                if(mapView!=null && sheetScroll!=null){
                    // Measure the real row width and scaled text before choosing
                    // the viewport; a fixed fraction can cut primary controls.
                    LinearLayout.LayoutParams map=(LinearLayout.LayoutParams)mapView.getLayoutParams();
                    LinearLayout.LayoutParams controls=(LinearLayout.LayoutParams)sheetScroll.getLayoutParams();
                    map.height=0;map.weight=sheetExpanded?0.30f:0.56f;
                    controls.height=0;controls.weight=sheetExpanded?0.70f:0.44f;
                }
                super.onMeasure(widthSpec,heightSpec);
                if(sheetScroll==null || primaryControls==null || sheetHandle==null)return;
                int available=mapView.getMeasuredHeight()+sheetScroll.getMeasuredHeight();
                LinearLayout.LayoutParams handle=(LinearLayout.LayoutParams)sheetHandle.getLayoutParams();
                LinearLayout.LayoutParams primary=(LinearLayout.LayoutParams)primaryControls.getLayoutParams();
                int minimum=sheet.getPaddingTop()+sheet.getPaddingBottom()
                        +sheetScroll.getPaddingTop()+sheetScroll.getPaddingBottom()
                        +sheetHandle.getMeasuredHeight()+handle.topMargin+handle.bottomMargin
                        +primaryControls.getMeasuredHeight()+primary.topMargin+primary.bottomMargin;
                int controlsHeight=Math.min(available,Math.max(minimum,
                        Math.round(available*(sheetExpanded?0.70f:0.44f))));
                LinearLayout.LayoutParams controls=(LinearLayout.LayoutParams)sheetScroll.getLayoutParams();
                LinearLayout.LayoutParams map=(LinearLayout.LayoutParams)mapView.getLayoutParams();
                controls.height=controlsHeight;controls.weight=0;
                map.height=available-controlsHeight;map.weight=0;
                super.onMeasure(widthSpec,heightSpec);
            }
        };root.setOrientation(LinearLayout.VERTICAL);root.setPadding(dp(10),dp(10),dp(10),dp(8));root.setBackgroundColor(Color.rgb(8,16,30));
        if(android.os.Build.VERSION.SDK_INT>=35) {
            // Current targets draw edge to edge. Keep both the map and controls
            // clear of navigation bars and landscape display cutouts.
            root.setOnApplyWindowInsetsListener((view,insets)->{
                android.graphics.Insets safe=insets.getInsets(android.view.WindowInsets.Type.systemBars() | android.view.WindowInsets.Type.displayCutout());
                view.setPadding(dp(10)+safe.left,dp(10)+safe.top,dp(10)+safe.right,dp(8)+safe.bottom);
                return insets;
            });
        }
        nodeButton=text("Add / select node",14,true);nodeButton.setTextColor(Color.WHITE);nodeButton.setPadding(dp(12),dp(9),dp(12),dp(9));nodeButton.setBackground(round(Color.rgb(24,38,62),16));nodeButton.setOnClickListener(v->showNodes());root.addView(nodeButton,margins(0,0,0,dp(8)));
        mapView=new RouterVpnNodeMapView(this);mapView.setOnMarkerClickListener(marker->{String raw=marker.id==null?"":marker.id;int cut=raw.indexOf(':');if(cut<=0)return;selectCatalog(raw.substring(0,cut),raw.substring(cut+1));});LinearLayout.LayoutParams mapParams=new LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT,0,0.56f);root.addView(mapView,mapParams);

        sheet=new LinearLayout(this);sheet.setOrientation(LinearLayout.VERTICAL);sheet.setPadding(dp(14),0,dp(14),dp(12));sheet.setBackground(round(Color.rgb(17,27,45),24));
        sheetScroll=new ScrollView(this);sheetScroll.setFillViewport(false);sheetScroll.setClipToPadding(false);sheetScroll.setOverScrollMode(View.OVER_SCROLL_IF_CONTENT_SCROLLS);sheetScroll.addView(sheet,new ScrollView.LayoutParams(ScrollView.LayoutParams.MATCH_PARENT,ScrollView.LayoutParams.WRAP_CONTENT));sheetScroll.setOnTouchListener((v,event)->{if(event.getAction()==MotionEvent.ACTION_DOWN){sheetTouchY=event.getY();return false;}if(event.getAction()==MotionEvent.ACTION_UP){float delta=event.getY()-sheetTouchY;if(Math.abs(delta)>dp(40)){sheetExpanded=delta<0;applySheetWeight();}return false;}return false;});LinearLayout.LayoutParams sheetParams=new LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT,0,0.44f);sheetParams.setMargins(0,dp(8),0,0);root.addView(sheetScroll,sheetParams);
        sheetHandle=text("━━━━━━━━",16,true);sheetHandle.setTextColor(Color.rgb(112,126,148));sheetHandle.setGravity(Gravity.CENTER);
        sheetHandle.setContentDescription("Expand connection controls");sheetHandle.setMinimumHeight(dp(48));sheetHandle.setFocusable(true);
        sheetHandle.setOnClickListener(v->{sheetExpanded=!sheetExpanded;applySheetWeight();});sheet.addView(sheetHandle);

        LinearLayout connectRow=row();primaryControls=connectRow;
        LinearLayout primaryAction=new LinearLayout(this);
        primaryAction.setOrientation(LinearLayout.VERTICAL);
        primaryAction.setGravity(Gravity.CENTER);
        killSwitch=new CheckBox(this);killSwitch.setText("Kill");killSwitch.setContentDescription("Kill switch");
        killSwitch.setTextColor(Color.WHITE);killSwitch.setButtonTintList(ColorStateList.valueOf(Color.rgb(123,104,255)));
        killSwitch.setOnClickListener(v -> setQuickKillSwitch(killSwitch.isChecked()));
        killSwitch.setSingleLine(false);
        connectRow.addView(killSwitch);
        connectButton=primaryButton("Connect");connectButton.setMinimumHeight(dp(50));connectButton.setOnClickListener(v->connectOrDisconnect());
        connectButton.setSingleLine(false);
        primaryAction.addView(connectButton,new LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT,LinearLayout.LayoutParams.WRAP_CONTENT));
        connectRow.addView(primaryAction,new LinearLayout.LayoutParams(0,LinearLayout.LayoutParams.WRAP_CONTENT,1f));
        liveLatency=text("-- ms",11,true);liveLatency.setTextColor(Color.rgb(173,190,214));liveLatency.setGravity(Gravity.CENTER);
        liveLatency.setPadding(dp(6),0,dp(6),0);liveLatency.setContentDescription("Current path response; tap for measurement details");
        liveLatency.setOnClickListener(v->showLiveTelemetry());primaryAction.addView(liveLatency);
        fastestButton=smallButton("Fastest ▾");fastestButton.setVisibility(View.GONE);fastestButton.setSingleLine(false);
        fastestButton.setContentDescription("Compare Router nodes by direct TCP, or compare external paths using 50 routed HTTPS responses.");
        fastestButton.setOnClickListener(v->showFastConnectMenu());
        connectRow.addView(fastestButton);
        forwardButton=smallButton("Forward");forwardButton.setContentDescription("Server port-forwarding master");forwardButton.setSingleLine(false);
        forwardButton.setOnClickListener(v->showForwarding());
        connectRow.addView(forwardButton);
        sheet.addView(connectRow);
        LinearLayout statusRow=row();statusView=text("Disconnected",13,false);statusView.setTextColor(Color.rgb(173,190,214));statusView.setTextIsSelectable(true);statusView.setOnClickListener(v->showConnectionDetails());statusRow.addView(statusView,new LinearLayout.LayoutParams(0,LinearLayout.LayoutParams.WRAP_CONTENT,1f));Button connectionDetails=smallButton("Details / proof");connectionDetails.setOnClickListener(v->showConnectionDetails());statusRow.addView(connectionDetails);sheet.addView(statusRow,margins(0,0,0,dp(7)));


        LinearLayout multiRow=row();multihopToggle=new CheckBox(this);multihopToggle.setText("Multihop");multihopToggle.setTextColor(Color.WHITE);multihopToggle.setButtonTintList(ColorStateList.valueOf(Color.rgb(55,145,255)));
        multihopToggle.setOnClickListener(v -> setQuickMultihop(multihopToggle.isChecked()));
        multiRow.addView(multihopToggle);multihopHint=text("Off",11,false);multihopHint.setTextColor(Color.rgb(173,190,214));multiRow.addView(multihopHint,new LinearLayout.LayoutParams(0,LinearLayout.LayoutParams.WRAP_CONTENT,1f));hopsButton=smallButton("Edit hops");hopsButton.setOnClickListener(v->{if(connection.isConnected())showLiveRoute();else configureMultihop();});multiRow.addView(hopsButton);sheet.addView(multiRow,margins(0,dp(8),0,0));
        multihopTotal=text("",12,true);multihopTotal.setOnClickListener(v->showLiveRoute());sheet.addView(multihopTotal);

        LinearLayout settingsRow=controlRow("Settings");Button settings=smallButton("Open settings");settings.setOnClickListener(v->showSettings());settingsRow.addView(settings);Button connectionProfiles=smallButton("Profiles");connectionProfiles.setContentDescription("Add, load, update or delete a whole non-secret connection profile");connectionProfiles.setOnClickListener(v->showConnectionProfiles());settingsRow.addView(connectionProfiles);performanceButton=smallButton("Performance");performanceButton.setOnClickListener(v->showPerformance());settingsRow.addView(performanceButton);Button mtu=smallButton("MTU");mtu.setOnClickListener(v->showMtuHelp());settingsRow.addView(mtu);sheet.addView(settingsRow,margins(0,dp(7),0,0));autoRequirementsHint=text("AUTO requirements: Off",11,false);autoRequirementsHint.setTextColor(Color.rgb(145,160,184));autoRequirementsHint.setPadding(dp(72),0,0,0);sheet.addView(autoRequirementsHint);
        LinearLayout modeRow=controlRow("Mode");modeSpinner=homeSpinner();modeRow.addView(modeSpinner,new LinearLayout.LayoutParams(0,LinearLayout.LayoutParams.WRAP_CONTENT,1f));Button modeDetails=smallButton("Presets");modeDetails.setOnClickListener(v->showCustomPresetManager());modeRow.addView(modeDetails);sheet.addView(modeRow,margins(0,dp(7),0,0));modeHint=text("SMART AUTO is the default.",11,false);modeHint.setTextColor(Color.rgb(145,160,184));sheet.addView(modeHint);
        LinearLayout dnsRow=controlRow("DNS");dnsSpinner=homeSpinner();dnsSpinner.setAdapter(homeChoices(dnsSpinner,java.util.Arrays.asList("Home AdGuard","Fastest measured","Custom","DoT","DoH","DoH3","Rescue")));dnsRow.addView(dnsSpinner,new LinearLayout.LayoutParams(0,LinearLayout.LayoutParams.WRAP_CONTENT,1f));Button dnsDetails=smallButton("Details");dnsDetails.setOnClickListener(v->{if(!openSelectedExternal(false))AndroidProductParity.showDNS(this,nodeStore,null,this::refreshDnsSelection);});dnsRow.addView(dnsDetails);sheet.addView(dnsRow,margins(0,dp(7),0,0));dnsHint=text("DNS changes the next tunnel resolver path; Connected still requires runtime DNS/path proof.",11,false);dnsHint.setTextColor(Color.rgb(145,160,184));sheet.addView(dnsHint);dnsSpinner.setOnItemSelectedListener(new android.widget.AdapterView.OnItemSelectedListener(){
            public void onNothingSelected(android.widget.AdapterView<?> parent){}
            public void onItemSelected(android.widget.AdapterView<?> parent,View view,int position,long id){selectHomeDns(position);}
        });
        LinearLayout speedRow=controlRow("Speed");Button speedLabButton=smallButton("Speed Lab");speedLabButton.setContentDescription("Run the dedicated current-path or temporary-config Speed Lab with idle and loaded latency, download/upload Mbps, and proved multihop hop metrics.");speedLabButton.setOnClickListener(v->new AndroidSpeedLabDialog(this,nodeStore,connection,new AndroidSpeedLabController(this,connection)).show());speedRow.addView(speedLabButton,new LinearLayout.LayoutParams(0,LinearLayout.LayoutParams.WRAP_CONTENT,1f));sheet.addView(speedRow,margins(0,dp(7),0,0));
        LinearLayout footer=row();Button nodes=smallButton("Nodes");nodes.setContentDescription("Add / manage nodes");nodes.setOnClickListener(v->showNodes());footer.addView(nodes);Button profiles=smallButton("Router nodes");profiles.setContentDescription("Manage linked Router VPN node records");profiles.setOnClickListener(v->showProfileManager());footer.addView(profiles);Button pair=smallButton("Add Router");pair.setOnClickListener(v->showAddRouter());footer.addView(pair);Button custom=smallButton("Add custom");custom.setOnClickListener(v->openStandardExits());footer.addView(custom);Button help=smallButton("Help");help.setOnClickListener(v->showHelp());footer.addView(help);sheet.addView(footer,margins(0,dp(8),0,0));return root;
    }

    private void applySheetWeight(){sheetHandle.setContentDescription(sheetExpanded?"Collapse connection controls":"Expand connection controls");((View)sheetScroll.getParent()).requestLayout();}
    private void refreshAll(){requestOrderedPresentation();refreshNodes();refreshFastestAvailability();refreshModeChoices();refreshConnectionState();refreshSettingsState();refreshDnsSelection();refreshMultihopSummary();refreshTelemetry(false);refreshLiveRoute();refreshForwardingState();}
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
        final String selected;
        try{selected=AndroidStartupPolicy.claimColdLaunch(this,nodeStore,restoredActivity,epoch);}
        catch(RuntimeException invalid){statusView.setText("Automatic startup stayed disconnected: "+safe(invalid));return;}
        if(selected==null)return;
        startupCapturePending=true;
        new Thread(()->{
            AndroidStartupPolicy.Attempt captured=null;Exception failure=null;
            try{captured=AndroidStartupPolicy.captureColdLaunch(this,nodeStore,connection,selected,epoch);}catch(Exception unavailable){failure=unavailable;}
            final AndroidStartupPolicy.Attempt capture=captured;final Exception error=failure;
            runOnUiThread(()->{
                if(ticket!=startupCaptureTicket||isFinishing()||isDestroyed()){if(capture!=null)capture.cancel();return;}
                startupCapturePending=false;
                // onResume may have rendered the capture as pending. A cold
                // launch without an eligible saved path must release that UI
                // state even though no connection callback will follow.
                refreshConnectionState();
                if(epoch!=AndroidStartupPolicy.captureEpoch()){if(capture!=null)capture.cancel();return;}
                if(error!=null){statusView.setText("Automatic startup stayed disconnected: "+safe(error));return;}
                if(capture!=null){
                    if(!capture.current()||!connection.pathCurrent(capture.idleOwner())){capture.cancel();return;}
                    statusView.setText("Preparing the captured startup path…");connection.connectStartup(capture,callback());
                }
            });
        },"routervpn-startup-capture").start();
    }

    private void connectOrDisconnect(){if(AndroidNodeCandidatePreparation.cancelActive()){connection.cancelPermissionPending();statusView.setText("Cancelling candidate testing; waiting for the temporary VPN to stop…");refreshConnectionLater();return;}if(orderedConnectCapturePending){orderedConnectCapturePending=false;orderedConnectTicket++;statusView.setText("Ordered connection capture was cancelled.");refreshConnectionLater();return;}if(startupCapturePending){startupCapturePending=false;startupCaptureTicket++;AndroidStartupPolicy.cancelPending();statusView.setText("Automatic startup was cancelled.");refreshConnectionLater();return;}if(AndroidExternalNodeComparison.cancelActiveOperation()){statusView.setText("Cancelling external comparison; retaining ownership through native drain and original restoration…");refreshConnectionLater();return;}if(connection.cancelStartupPending()||connection.cancelPermissionPending()){refreshConnectionLater();return;}AndroidStartupPolicy.cancelPending();if(AndroidViaEntryLatencyProbe.cancelActiveOperation()){statusView.setText("Cancelling the captured candidate test; waiting for owned sockets and entry teardown…");refreshConnectionLater();return;}if(connection.isActiveOrTransitioning()){statusView.setText("Disconnecting…");connectButton.setText("Disconnecting…");connection.disconnect(callback());return;}AndroidUnifiedNodeCatalog.Item selected=selectedCatalogItem();if(selected==null){showNodes();return;}if(!selected.isRouterVpn()){try{AndroidConnectionProfileStore.ExternalSelection path=new AndroidConnectionProfileStore(this,nodeStore,exitStore).currentExternalPath(selected.id);statusView.setText("Preparing external path…");connection.connectExternal(path,callback());}catch(Exception error){toast(safe(error));}return;}if(multihopToggle.isChecked()){try{if(!prefs().getString("multihop_nodes","").isEmpty()){connectSavedOrderedPath();return;}if("external".equals(prefs().getString("multihop_entry_kind","router-vpn"))){AndroidConnectionProfileStore.ImportedRouterSelection path=new AndroidConnectionProfileStore(this,nodeStore,exitStore).currentImportedRouterPath();statusView.setText("Preparing imported entry → Router final…");connection.connectImportedMultihop(path.entry,path.exit,path.exitMode,path.execution,callback());return;}AndroidNodeStore.Node entry=nodeById(prefs().getString(MULTI_ENTRY,"")),exit=nodeById(prefs().getString(MULTI_EXIT,""));String exitMode=prefs().getString(MULTI_MODE,"");if(entry==null||exit==null||exitMode.isEmpty()){configureMultihop();return;}statusView.setText("Preparing multihop…");connection.connectMultihop(entry,exit,exitMode,prefs().getString("multihop_execution","local"),prefs().getString("multihop_entry_mode","wg"),callback());}catch(Exception error){toast(safe(error));}return;}refreshModeChoices();ModeChoice choice=currentMode();if(choice==null){statusView.setText("Saved mode unavailable. Select an available mode or restore its preset before connecting.");return;}statusView.setText("Preparing "+choice.title+"…");connection.connect(choice.id,choice.layers,callback());}
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
    private void refreshConnectionState(){boolean active=connection!=null&&connection.isActiveOrTransitioning(),busy=mutationBusy(),candidate=AndroidNodeCandidatePreparation.busy()||AndroidViaEntryLatencyProbe.hasActiveOperation()||AndroidExternalNodeComparison.hasActiveOperation(),startup=startupCapturePending||connection!=null&&connection.isStartupPending(),permission=orderedConnectCapturePending||connection!=null&&connection.isPermissionPending();connectButton.setText(startup?"Cancel startup":candidate?"Cancel test":permission?"Cancel connection":active?"Disconnect":"Connect");nodeButton.setEnabled(!busy);fastestButton.setEnabled((!busy||connection.isConnected())&&!candidate&&!permission&&!startup&&!AndroidMTUMeasurementGate.held());killSwitch.setEnabled(!busy);multihopToggle.setEnabled(!busy);modeSpinner.setEnabled(!busy&&!isExternalSelected()&&!(prefs().getBoolean(MULTI_ON,false)&&!prefs().getString("multihop_nodes","").isEmpty()));dnsSpinner.setEnabled(!busy&&!isExternalSelected());if(startupCapturePending)statusView.setText("Checking saved startup settings…");else if(startup)statusView.setText("Waiting for Android permission for the captured startup path. Cancel startup keeps the app disconnected.");else if(AndroidNodeCandidatePreparation.busy())statusView.setText("Testing saved path. Cancel test waits for the temporary VPN and candidate connections to stop.");else if(permission)statusView.setText("Waiting for Android permission for the captured connection. Cancel connection keeps the app disconnected.");else if(!candidate)statusView.setText(AndroidHomeSummary.status(this,nodeStore,isExternalSelected()));else if(AndroidExternalNodeComparison.hasActiveOperation())statusView.setText("Comparing captured external paths. Cancel test waits for native cleanup and original restoration.");else if(!viaEntryProbe.isBusy())statusView.setText("A captured candidate test is draining. Cancel test retries only its temporary entry cleanup.");if(!connection.isConnected()){liveLatency.setText("-- ms");}}

    private void showConnectionDetails(){String truth=AndroidHomeSummary.format(this,nodeStore)+multihopExecutionSummary();new AlertDialog.Builder(this).setTitle("Connection details & proof").setMessage(truth+"\n\nConnected is not treated as a proved public exit until the current app-owned VPN network, frozen session node/path and current-session exit proof all agree.").setPositiveButton("Prove actual exit",(d,w)->{statusView.setText("Proving actual public VPN exit for this session…");AndroidHomeSummary.proveActualExit(this,nodeStore,(message,error)->runOnUiThread(()->{statusView.setText(message);if(error!=null)toast(message);refreshAll();}));}).setNeutralButton("Emergency disconnect",(d,w)->{statusView.setText("Emergency disconnect requested…");AndroidHomeSummary.emergencyDisconnect(this,(message,error)->runOnUiThread(()->{statusView.setText(message);if(error!=null)toast(message);refreshAll();refreshConnectionLater();}));}).setNegativeButton("Close",null).show();}

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
        fastestButton.setEnabled(false);fastestButton.setText("Testing…");
        final AlertDialog progress=new AlertDialog.Builder(this).setTitle(chooseNode?"Find fastest Router node":"Compare Router nodes")
            .setMessage("Collecting 50 TCP responses per node on one captured physical network. The lowest 10% trimmed mean wins; incomplete nodes receive no score. Saved benchmark statistics are preserved.")
            .setCancelable(false).setNegativeButton("Cancel measurement",null).create();
        fastestProgressDialog=progress;
        progress.setOnDismissListener(d->{if(fastestProgressDialog==progress)telemetry.cancelFastest();});
        progress.show();
        progress.getButton(AlertDialog.BUTTON_NEGATIVE).setOnClickListener(v->{telemetry.cancelFastest();progress.setMessage("Cancelling; waiting for the captured sockets to drain…");progress.getButton(AlertDialog.BUTTON_NEGATIVE).setEnabled(false);});
        telemetry.measureFastest((values,error)->runOnUiThread(()->{
            if(fastestProgressDialog!=progress||isFinishing()||isDestroyed())return;
            fastestProgressDialog=null;progress.dismiss();fastestButton.setEnabled(true);fastestButton.setText("Fastest ▾");refreshNodes();
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

    private void clearCurrentTelemetry(){currentPathReceipt=null;currentExternalReceipt=null;liveLatency.setText("-- ms");}
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
            try{if(error!=null)throw new IllegalStateException(safe(error));if(path==null)throw new IllegalStateException("No current RTT result.");path.requireCurrent();currentPathReceipt=path;liveLatency.setText(String.format(Locale.US,"%.1f ms%s",path.medianMs,path.publicExitId.isEmpty()?"":" HTTPS"));}
            catch(Exception stale){clearCurrentTelemetry();}
            refreshMultihopSummary();refreshLiveRoute();
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
            try{if(error!=null)throw new IllegalStateException(safe(error));if(result==null)throw new IllegalStateException("No current HTTPS response.");result.requireCurrent();currentExternalReceipt=result;currentPathReceipt=null;liveLatency.setText(String.format(Locale.US,"%.1f ms HTTPS",result.medianMs));}
            catch(Exception stale){clearCurrentTelemetry();}
            refreshMultihopSummary();refreshMap();refreshLiveRoute();
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
            try{if(e!=null)throw new IllegalStateException(safe(e));r.requireCurrent();dialog(r.publicExitId.isEmpty()?"Live tunnel RTT":"Live HTTPS path response",String.format(Locale.US,"Median %.1f ms • %d ok / %d failed\n%s",r.medianMs,r.samples,r.failed,r.proof));}
            catch(Exception stale){dialog("Live tunnel RTT",safe(stale));}
        }));
    }
    private void showLiveRoute() {
        if(liveRouteDialog!=null)liveRouteDialog.dismiss();
        AlertDialog.Builder builder=new AlertDialog.Builder(this);
        liveRouteDetails=new TextView(builder.getContext());liveRouteDetails.setPadding(dp(24),dp(16),dp(24),dp(8));
        liveRouteDetails.setTextIsSelectable(true);
        ScrollView routeScroll=new ScrollView(builder.getContext());routeScroll.addView(liveRouteDetails);
        liveRouteDialog=builder.setTitle("Multihop path").setView(routeScroll).setNegativeButton("Close",null).create();
        liveRouteDialog.setOnDismissListener(d->{liveRouteDialog=null;liveRouteDetails=null;});
        refreshLiveRoute();liveRouteDialog.show();refreshTelemetry(true);
    }
    private void refreshLiveRoute() {
        if(multihopTotal==null)return;
        hopsButton.setText(connection.isConnected()?"View path":"Edit hops");
        AndroidHomeStateStore.Snapshot home=AndroidHomeStateStore.snapshot(this);
        boolean external="external".equals(home.logicalMode);
        boolean multihop=connection.isConnected()&&("node-chain".equals(home.logicalMode)||"multihop".equals(home.logicalMode)
                ||external&&!home.activeEntryId.isEmpty());
        String total="Connect a multihop path to measure its total response.";
        if(multihop) {
            total="Total path response unavailable";
            try {
                if(external&&currentExternalReceipt!=null&&currentExternalReceipt.id.equals(home.activeExternalId)){
                    currentExternalReceipt.requireCurrent();
                    total=String.format(Locale.US,"Total path response • %.1f ms HTTPS",currentExternalReceipt.medianMs);
                } else if(!external&&currentPathReceipt!=null) {
                    currentPathReceipt.requireCurrent();
                    total=String.format(Locale.US,"Total path response • %.1f ms %s",currentPathReceipt.medianMs,currentPathReceipt.publicExitId.isEmpty()?"HTTP to final node":"public HTTPS");
                }
            } catch(Exception stale) { /* The next current-session poll may provide a new receipt. */ }
        }
        multihopTotal.setVisibility(multihop?View.VISIBLE:View.GONE);multihopTotal.setText(total);
        if(liveRouteDetails!=null){
            String details=multihop?multihopHint.getText()+"\n\n"+total:total;
            AndroidOrderedPathPresentation presentation="node-chain".equals(home.logicalMode)?currentOrderedPresentation():null;
            if(multihop&&presentation!=null&&presentation.live&&!presentation.comparisonDetails.isEmpty())details+="\n\n"+presentation.comparisonDetails;
            liveRouteDetails.setText(details);
        }
    }

    private void showPerformance(){
        String[] actions={"Live current path response","50-sample selected node","Compare all Router nodes (50 TCP)","Real current VPN path speed","Routed multihop speeds","Path throughput / Auto MTU status","Last saved 50-sample statistics","Compare all external exits (50 HTTPS)","Compare and connect fastest external path","Test candidates through a saved or connected prefix","Ordered path: Fifty / Retest per node"};
        choiceDialog("Performance","Router node benchmarks use direct TCP while disconnected. A selected external node uses 50 HTTPS responses through its connected, proved native path and selected DNS. These saved measurement types remain separate; external HTTPS results do not enter direct TCP Fastest or Lowest latency rankings. Ordered Fifty measures the selected prefix: private responses include connection setup; public HTTPS responses start after TLS. Its history is separate from direct TCP rankings. Current-path RTT and throughput are separate actions.").setItems(actions,(d,w)->{
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
            else if(w==10){runOrderedLatency();}
            else{JSONObject p=activeRouterProfile();if(p==null){toast("Select a Router VPN node first.");return;}double mbps=p.optDouble("effective_mtu_mbps",0),rtt=p.optDouble("effective_mtu_median_rtt_ms",0);int mtu=p.optInt("effective_mtu",0);String value=mbps>0?String.format(Locale.US,"Last MTU-path optimizer result: %.1f Mbps • MTU %d • RTT %.1f ms\n\nThis is separate from the real 8 MiB down/up path speed test.",mbps,mtu,rtt):"No proven Auto-MTU optimizer result is stored for this path yet. Open Settings / MTU to configure Auto or Fixed MTU. Real path Mbps is a separate Performance action.";dialog("Path throughput / Auto MTU",value);}
        }).setNegativeButton("Close",null).show();
    }

    private void runCurrentSpeed(){
        if(!connection.isConnected()){toast("Connect Router VPN before testing current path speed.");return;}
        if(connection.isOrderedConnected()){runRoutedHopSpeeds();return;}
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
                if(w==4){if(mutationBusy()){toast("Disconnect/finish before changing the selected node.");return;}try{AndroidUnifiedNodeCatalog.Item lowest=catalog.lowestLatency();if(lowest==null){toast("Measure at least two Router nodes with 50 successful samples first.");return;}if(!selectCatalog(lowest))return;toast("Selected "+lowest.name+" from saved 50-sample trimmed means. Saved times/networks may differ; use Fastest for a current comparison. Press Connect when ready.");}catch(Exception error){toast(safe(error));}return;}
                if(w==5){AndroidConnectionProfileStore.applySelection(prefs(),prefs().edit().putString("node_sort",AndroidUnifiedNodeCatalog.SORT_MOST_USED));showNodes();return;}
                AndroidConnectionProfileStore.applySelection(prefs(),prefs().edit().putString("node_sort",new String[]{AndroidUnifiedNodeCatalog.SORT_CURRENT,AndroidUnifiedNodeCatalog.SORT_LAST_USED,AndroidUnifiedNodeCatalog.SORT_NAME,AndroidUnifiedNodeCatalog.SORT_LATENCY}[w]));showNodes();
            }).setNegativeButton("Close",null).show();
    }

    private void runCandidateTimes(){closeCandidateMeasurement();detachCandidatePreparation();if(AndroidNodeCandidatePreparation.retained()!=null||!connection.isConnected()){preparedCandidateDialog=new AndroidNodeCandidatePreparationDialog(this,nodeStore,connection,this::refreshConnectionLater,this::continueOrderedDraft);preparedCandidateDialog.show();}else{candidateDialog=new AndroidNodeCandidateDialog(this);candidateDialog.show();}}
    private void resumeCandidatePreparation(){if(orderedPicker!=null&&orderedPicker.visible())return;if(AndroidNodeCandidatePreparation.retained()!=null){detachCandidatePreparation();preparedCandidateDialog=new AndroidNodeCandidatePreparationDialog(this,nodeStore,connection,this::refreshConnectionLater,this::continueOrderedDraft);preparedCandidateDialog.show();}}
    private void detachCandidatePreparation(){if(preparedCandidateDialog!=null){preparedCandidateDialog.detach();preparedCandidateDialog=null;}}

    private void closeOrderedPicker(){if(orderedPicker!=null){orderedPicker.close();orderedPicker=null;}}
    private void closeCandidateMeasurement(){AndroidNodeCandidateDialog owned=candidateDialog;candidateDialog=null;if(owned!=null)owned.close();}

    private void runOrderedLatency(){closeOrderedLatency();orderedLatencyDialog=new AndroidOrderedLatencyDialog(this);orderedLatencyDialog.show();}
    private void closeOrderedLatency(){AndroidOrderedLatencyDialog owned=orderedLatencyDialog;orderedLatencyDialog=null;if(owned!=null)owned.close();}

    private void runRoutedHopSpeeds(){
        if(!connection.isMultihopConnected()&&!connection.isOrderedConnected()){toast("Connect the actual Android multihop graph before testing routed hop speeds.");return;}
        closeRoutedHopMeasurement();
        routedHopDialog=new AndroidHopMeasurementDialog(this,connection);
        routedHopDialog.show();
    }

    private void closeRoutedHopMeasurement(){
        AndroidHopMeasurementDialog owned=routedHopDialog;routedHopDialog=null;
        if(owned!=null)owned.close();
    }

    private void refreshModeChoices(){
        modeSpinner.setOnItemSelectedListener(null);
        if(orderedPathEnabled()) {
            modeChoices=new ArrayList<>();modeChoices.add(new ModeChoice("node-chain","Per-hop transports • ordered path"));
            modeSpinner.setAdapter(homeChoices(modeSpinner,modeChoices));modeSpinner.setSelection(0,false);modeSpinner.setEnabled(false);
            modeHint.setText("Each ordered node keeps its selected transport. Use Edit hops to change the path; the single-node mode is remembered separately.");return;
        }
        AndroidUnifiedNodeCatalog.Item external=selectedCatalogItem();if(external!=null&&!external.isRouterVpn()){modeChoices=new ArrayList<>();modeChoices.add(new ModeChoice("external",external.protocol+" • saved external protocol"));modeSpinner.setAdapter(homeChoices(modeSpinner,modeChoices));modeSpinner.setSelection(0,false);modeHint.setText("Saved external protocol and path; edit DNS and device policy in Settings.");return;}
        String wanted = prefs().getString(MODE_KEY, "smart-auto");
        List<ModeChoice> values = new ArrayList<>();
        values.add(new ModeChoice("smart-auto", "SMART AUTO — recommended"));
        values.add(new ModeChoice("auto", "AUTO — first proven path"));
        try {
            JSONArray logical = activeBundle().optJSONArray("logicalModes");
            if (logical != null) for (int i = 0; i < logical.length(); i++) {
                JSONObject item = logical.optJSONObject(i);
                if (item == null) continue;
                String id = item.optString("id", "");
                if (!id.isEmpty()) values.add(new ModeChoice(id, item.optString("name", id)));
            }
        } catch (Exception ignored) {}
        for (CustomPreset p : loadCustomPresets()) values.add(new ModeChoice("custom:"+p.name,"CUSTOM • "+p.name,p.layers));
        int index = 0;
        while (index < values.size() && !values.get(index).id.equals(wanted)) index++;
        if (index == values.size()) {
            values.add(new ModeChoice(wanted, "Unavailable • " + wanted, Collections.emptyList(), false));
            modeHint.setText("The saved mode is unavailable on this node. Select an available mode or restore its preset.");
        } else {
            modeHint.setText(wanted.startsWith("custom:") ? "Saved visual CUSTOM preset • exact required layers" : "The selected mode must pass its runtime and path checks.");
        }
        values.add(new ModeChoice(CREATE_CUSTOM_ACTION,"New CUSTOM preset…"));
        modeChoices = values;
        ArrayAdapter<ModeChoice> adapter = homeChoices(modeSpinner,values);
        modeSpinner.setAdapter(adapter);
        modeSpinner.setSelection(index, false);
        final int initialIndex=index;
        modeSpinner.setOnItemSelectedListener(new android.widget.AdapterView.OnItemSelectedListener(){
            int displayedIndex=initialIndex;
            public void onNothingSelected(android.widget.AdapterView<?> parent){}
            public void onItemSelected(android.widget.AdapterView<?> parent,View view,int pos,long id){
                if(modeSpinner.getAdapter()!=adapter||pos<0||pos>=modeChoices.size()||pos!=modeSpinner.getSelectedItemPosition()||pos==displayedIndex)return;
                if(mutationBusy()){toast("Disconnect/finish the current VPN operation before changing the next connection mode or CUSTOM preset.");refreshModeChoices();return;}
                ModeChoice selected=modeChoices.get(pos);
                if (!selected.available) {
                    modeSpinner.setSelection(displayedIndex, false);
                    toast("Restore the missing mode or choose an available one.");
                    return;
                }
                if(CREATE_CUSTOM_ACTION.equals(selected.id)){
                    modeSpinner.setSelection(displayedIndex,false);
                    showCustomBuilder(null);
                    return;
                }
                AndroidConnectionProfileStore.applySelection(prefs(),prefs().edit().putString(MODE_KEY,selected.id));
                displayedIndex=pos;
                modeHint.setText(selected.id.startsWith("custom:")?"Saved visual CUSTOM preset • exact required layers":"Unavailable presets remain visible; the engine fails closed with the exact readiness/proof reason.");
            }
        });
    }
    private ModeChoice currentMode(){
        if(modeSpinner==null||modeChoices.isEmpty())return null;
        String saved=prefs().getString(MODE_KEY,"smart-auto");
        ModeChoice found = null;
        for (ModeChoice choice : modeChoices) {
            if (!choice.available || !choice.id.equals(saved) || CREATE_CUSTOM_ACTION.equals(saved)) continue;
            if (found != null) return null;
            found = choice;
        }
        return found;
    }
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
                try { deleteCustomPreset(editing); dialog.dismiss(); refreshModeChoices(); }
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
        if (!AndroidCustomPresetCommit.validName(clean)) { toast("Use a safe 1–64 character preset name."); return; }
        if (selected.isEmpty()) { toast("CUSTOM requires at least one layer."); return; }
        CustomPreset preset = new CustomPreset(clean, selected);
        try { saveCustomPreset(preset, editing); }
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
            List<String> mapOrder=new ArrayList<>();AndroidOrderedPathPresentation presentation=currentOrderedPresentation();boolean liveOrdered=presentation!=null&&presentation.live;
            if(presentation!=null) {
                for(AndroidOrderedPathPresentation.Member member:presentation.members)
                    mapOrder.add((member.imported?AndroidUnifiedNodeCatalog.KIND_EXTERNAL:AndroidUnifiedNodeCatalog.KIND_ROUTER_VPN)+":"+member.id);
                selectedKind=AndroidUnifiedNodeCatalog.KIND_ROUTER_VPN;selectedId=presentation.members.get(presentation.members.size()-1).id;
            }
            boolean live=liveOrdered;
            java.util.function.BooleanSupplier frameOwner=liveOrdered ? () -> presentation.current(this) : null;
            if(presentation==null) {
                AndroidHomeStateStore.Snapshot home=AndroidHomeStateStore.snapshot(this);
                List<String> active=connection.activeMapPair(home);
                if(!active.isEmpty()) {
                    mapOrder.addAll(active);
                    live=true;
                    frameOwner=()->AndroidHomeStateStore.ownsPairFrame(this,home);
                } else if(prefs().getBoolean(MULTI_ON,false)&&prefs().getString("multihop_nodes","").isEmpty()) {
                    String entry=prefs().getString(MULTI_ENTRY,""),exit=prefs().getString(MULTI_EXIT,"");
                    if(!entry.isEmpty()&&!exit.isEmpty()) {
                        mapOrder.add(prefs().getString("multihop_entry_kind","router-vpn")+":"+entry);
                        mapOrder.add(selectedKind+":"+exit);
                    }
                }
            }
            List<RouterVpnNodeMapView.Marker> markers=new ArrayList<>();AndroidUnifiedNodeCatalog.Item chosen=null;
            for(AndroidUnifiedNodeCatalog.Item item:items) {
                if(item.kind.equals(selectedKind)&&item.id.equals(selectedId))chosen=item;
                if(!item.hasCoordinates())continue;
                int position=presentation==null?-1:mapOrder.indexOf(item.kind+":"+item.id);String role;
                if(position>=0)role=position==0?RouterVpnNodeMapView.ROLE_ENTRY:position==mapOrder.size()-1?RouterVpnNodeMapView.ROLE_EXIT:RouterVpnNodeMapView.ROLE_HOP;
                else if(presentation==null&&mapOrder.size()==2&&mapOrder.get(0).equals(item.kind+":"+item.id))role=RouterVpnNodeMapView.ROLE_ENTRY;
                else if(presentation==null&&mapOrder.size()==2&&mapOrder.get(1).equals(item.kind+":"+item.id))role=RouterVpnNodeMapView.ROLE_EXIT;
                else if(item.id.equals(selectedId)&&item.kind.equals(selectedKind))role=RouterVpnNodeMapView.ROLE_SELECTED;
                else if(!item.isRouterVpn())role=RouterVpnNodeMapView.ROLE_EXTERNAL;
                else role=RouterVpnNodeMapView.ROLE_NORMAL;
                boolean routedPair=live && presentation==null && (RouterVpnNodeMapView.ROLE_ENTRY.equals(role)||RouterVpnNodeMapView.ROLE_EXIT.equals(role));
                double ms=0;
                String metric;
                if(position>=0) {
                    ms=presentation.members.get(position).httpResponseMs;
                    metric=item.isRouterVpn()?"HTTP proof at startup":"public-path proof at startup";
                } else if(item.isRouterVpn()) {
                    if(!routedPair) {
                        ms=telemetry==null?0:telemetry.cachedMedian(item.id);
                        if(ms<=0 && item.hasMeasuredLatency())ms=item.latencyMedianMs;
                    }
                    metric="direct TCP";
                } else {
                    ms=liveExternalMedian(item.id);
                    metric="routed HTTPS";
                }
                String name=(position>=0?(presentation.testing?(presentation.members.get(position).testing?"Testing • ":"Saved • "):"")+(position+1)+". ":"")+item.name;
                markers.add(new RouterVpnNodeMapView.Marker(item.kind+":"+item.id,name,item.latitude,item.longitude,role,ms,!item.isRouterVpn(),metric));
            }
            mapView.setMarkers(markers);mapView.setOrderedPath(mapOrder,live,frameOwner);
            double chosenMs=presentation!=null?0:chosen==null?0:!chosen.isRouterVpn()?liveExternalMedian(chosen.id):telemetry!=null?telemetry.cachedMedian(chosen.id):chosen.hasMeasuredLatency()?chosen.latencyMedianMs:0;
            nodeButton.setText(chosen==null?"Add / select node":(chosen.isRouterVpn()?"Router • ":"Custom • ")+chosen.name+(chosen.location.isEmpty()?"":" • "+chosen.location)+(chosenMs>0?String.format(Locale.US," • %.1f ms%s",chosenMs,chosen.isRouterVpn()?"":" HTTPS"):"")+"  ▾");
        } catch(Exception error) {
            nodeButton.setText("Node catalog unavailable");mapView.setMarkers(new ArrayList<>());mapView.setOrderedPath(new ArrayList<>(),false,null);
        }
    }
    private void refreshFastestAvailability() {
        if(!resumed)return;
        final String key;
        try{key=fastestCatalogIdentity();}
        catch(Exception changed){fastestCatalogKey="";fastestButton.setVisibility(View.GONE);return;}
        if(key.equals(fastestCatalogKey))return;
        fastestCatalogKey=key;long ticket=++fastestCatalogTicket;fastestButton.setVisibility(View.GONE);
        new Thread(()->{
            boolean eligible=false;
            try{eligible=hasFastestComparison(catalog.list(AndroidUnifiedNodeCatalog.SORT_CURRENT));}catch(Exception unavailable){}
            final boolean available=eligible;
            runOnUiThread(()->{
                if(ticket!=fastestCatalogTicket||!resumed||isFinishing()||isDestroyed())return;
                try{if(!key.equals(fastestCatalogIdentity())){refreshFastestAvailability();return;}}
                catch(Exception changed){fastestCatalogKey="";return;}
                fastestButton.setVisibility(available?View.VISIBLE:View.GONE);
            });
        },"routervpn-fastest-availability").start();
    }
    private String fastestCatalogIdentity() throws Exception {
        return AndroidNodeStore.publicationGeneration()+"/"+AndroidStandardExitStore.publicationGeneration()+"/"+AndroidConnectionSelection.digest(this,nodeStore);
    }
    private boolean hasFastestComparison(List<AndroidUnifiedNodeCatalog.Item> items) throws Exception {
        int routers=0,external=0;
        for(AndroidUnifiedNodeCatalog.Item item:items) {
            if(item.isRouterVpn()){if(!item.endpoint.trim().isEmpty()&&++routers>=2)return true;}
            else external++;
        }
        if(external<2)return false;
        // A comparison uses one entry context and a single measurement type.
        // A Router TCP sample and an external HTTPS response cannot compete.
        AndroidConnectionProfileStore.ExternalSelection path=null;
        if(isExternalSelected())try{path=new AndroidConnectionProfileStore(this,nodeStore,exitStore).currentExternalPath(prefs().getString(SELECTED_ID,""));}catch(Exception unavailable){}
        int direct=0,via=0;
        for(AndroidStandardExitStore.Entry exit:exitStore.list()) {
            try{AndroidConnectionProfileStore.validateExternalGraph(exit,null,null,"wg","local");direct++;}
            catch(Exception unavailable){}
            if(path!=null&&!path.direct())try{AndroidConnectionProfileStore.validateExternalGraph(exit,path.entry,path.ordinaryEntry,path.entryMode,path.execution);via++;}
            catch(Exception unavailable){}
            if(direct>=2||via>=2)return true;
        }
        return false;
    }
    private void refreshMap(){refreshNodes();}
    private AndroidUnifiedNodeCatalog.Item selectedCatalogItem(){try{String kind=prefs().getString(SELECTED_KIND,"router-vpn"),id=prefs().getString(SELECTED_ID,nodeStore.activeId());for(AndroidUnifiedNodeCatalog.Item item:catalog.list(AndroidUnifiedNodeCatalog.SORT_CURRENT))if(item.kind.equals(kind)&&item.id.equals(id))return item;}catch(Exception ignored){}return null;}
    private void selectCatalog(String kind,String id){try{for(AndroidUnifiedNodeCatalog.Item item:catalog.list(AndroidUnifiedNodeCatalog.SORT_CURRENT))if(item.kind.equals(kind)&&item.id.equals(id)){selectCatalog(item);return;}}catch(Exception error){toast(safe(error));}}
    private boolean selectCatalog(AndroidUnifiedNodeCatalog.Item item) {
        if (mutationBusy()) {
            toast("Disconnect/finish the current VPN operation before changing the selected node; live/probe identity is frozen.");
            return false;
        }
        try {
            synchronized (prefs()) {
                if (item.isRouterVpn()) nodeStore.select(item.id);
                android.content.SharedPreferences.Editor selected = prefs().edit()
                        .putString(SELECTED_KIND, item.kind).putString(SELECTED_ID, item.id);
                if (!item.kind.equals(prefs().getString(SELECTED_KIND, "")) || !item.id.equals(prefs().getString(SELECTED_ID, ""))) {
                    selected.putBoolean(MULTI_ON, false).putString(MULTI_ENTRY, "").putString(MULTI_EXIT, "").putString("multihop_nodes", "");
                }
                AndroidConnectionProfileStore.applySelection(prefs(), selected);
            }
            refreshAll();
            return true;
        } catch (Exception error) {
            toast(safe(error));
            return false;
        }
    }
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

    private AlertDialog orderedEditorDialog;
    private void showOrderedEditor(AndroidOrderedPathSelection draft) {
        try {
            if(mutationBusy())throw new IllegalStateException("Finish the current VPN operation before editing its ordered nodes.");
            draft.requireCurrent();List<AndroidOrderedPathSelection.Member> members=draft.members();
            List<String> labels=new ArrayList<>();List<Integer> actions=new ArrayList<>();
            for(int i=0;i<members.size();i++) {
                AndroidOrderedPathSelection.Member member=members.get(i);
                String name=member.source.profile().optString("name",member.source.profileId);
                labels.add((i+1)+". "+name+" • "+(!draft.unfinished()&&i==members.size()-1?"Final • "+AndroidOrderedPathSelection.finalModeTitle(member.mode):AndroidOrderedPathSelection.prefixModeTitle(member.mode)));
                actions.add(i);
            }
            if(draft.unfinished()) {
                if(draft.canAddPrefix()){labels.add("Add prefix node");actions.add(-2);}
                if(!members.isEmpty()&&members.size()<AndroidNodeStore.PHYSICAL_TRAVERSAL_DEPTH){labels.add("Measure next node");actions.add(-4);}
                if(!members.isEmpty()){labels.add("Choose final Router node");actions.add(-1);}
                if(draft.canCompleteAppend()){labels.add("Use last "+AndroidOrderedPathSelection.finalModeTitle(members.get(members.size()-1).mode)+" node as final");actions.add(-5);}
            } else {
                if(members.isEmpty()){labels.add("Choose final Router node");actions.add(-1);}
                else if(draft.canAddPrefix()){labels.add("Add another intermediate node");actions.add(-2);}
                labels.add("Start a prefix-only draft");actions.add(-3);
            }
            if(orderedEditorDialog!=null && orderedEditorDialog.isShowing())orderedEditorDialog.dismiss();
            String help=draft.unfinished()
                    ?"This draft contains only the real prefix shown above. Choose the next paired WireGuard, AmneziaWG, Shadowsocks 2022 or Hysteria2 transport with Start Layer Off, or explicitly choose an imported Shadowsocks 2022 node, then measure candidates through this prefix, and apply a result after the temporary VPN has stopped. Choose a real final node before saving a complete path. The selected saved connection stays unchanged until Save."
                    :"Start with two nodes. Tap a hop to edit it or measure candidates through a supported prefix. Save path keeps your choice for Connect.\n\n"
                    +"Most paths support two to eight nodes. Longer Local paths can use paired WireGuard hops, or begin with paired WireGuard or AmneziaWG hops followed by imported and paired Shadowsocks 2022 streams. These paths end at a paired Shadowsocks 2022 node and require Start Layer Off. The native source, MTU and traversal limits apply.\n\n"
                    +"A three-node Local path can start with two distinct saved Shadowsocks 2022 nodes with literal IPs and Start Layer Off. It ends at a paired Shadowsocks 2022 node.";
            orderedEditorDialog=choiceDialog(draft.unfinished()?"Unfinished Router prefix":"Ordered Router path",help)
                    .setItems(labels.toArray(new CharSequence[0]),(d,w)->{
                        int action=actions.get(w);
                        if(action==-5){completeOrderedAppend(draft);return;}
                        if(action==-4){measureOrderedAppend(draft);return;}
                        if(action==-3){chooseOrderedPrefixStart(draft);return;}
                        if(action==-2){chooseOrderedNode(draft,false);return;}
                        if(action==-1||!draft.unfinished()&&action==members.size()-1){chooseOrderedNode(draft,true);return;}
                        editOrderedPrefix(draft,action);
                    }).setNeutralButton(draft.unfinished()?"Start over":"Execution: "+AndroidOrderedPathSelection.executionTitle(draft.execution()),
                            (d,w)->{if(draft.unfinished())chooseOrderedPrefixStart(draft);else chooseOrderedExecution(draft);})
                    .setPositiveButton(draft.unfinished()?"Choose final":"Save path",(d,w)->{
                        if(draft.unfinished()){if(draft.members().isEmpty())chooseOrderedPrefixStart(draft);else chooseOrderedNode(draft,true);return;}
                        try{if(mutationBusy())throw new IllegalStateException("The VPN state changed before saving the ordered path.");draft.save();refreshAll();statusView.setText("Ordered path saved. Press Connect to prove every selected node.");}
                        catch(Exception error){toast(safe(error));}
                    }).setNegativeButton("Cancel",null).show();
        } catch(Exception error) { toast(safe(error)); }
    }

    private void completeOrderedAppend(AndroidOrderedPathSelection draft) {
        try {
            if(mutationBusy()||AndroidNodeCandidatePreparation.retained()!=null||AndroidMTUMeasurementGate.held())
                throw new IllegalStateException("Close the current candidate review and wait for its original cleanup, then use the last node as final.");
            draft.requireCurrent();
            final long revision=draft.revision();
            final AndroidHomeStateStore.Snapshot home=AndroidHomeStateStore.snapshot(this);
            final AndroidDeviceMTU deviceMTU=AndroidDeviceMTU.capture(this);
            final String selection=AndroidConnectionSelection.digest(this,nodeStore);
            if(home.connected||!home.sessionId.isEmpty()||!"off".equals(home.phase))throw new IllegalStateException("Wait for the original tunnel to return to Disconnected.");
            Runnable current=()->{
                if(!resumed||isFinishing()||isDestroyed()||mutationBusy()||AndroidNodeCandidatePreparation.retained()!=null
                        ||AndroidMTUMeasurementGate.held()||!connection.pathCurrent(home)||draft.revision()!=revision||!draft.unfinished())
                    throw new IllegalStateException("The original idle editor or VPN owner changed before completion.");
                deviceMTU.requireCurrent(this);
                try{AndroidConnectionSelection.requireCurrent(this,nodeStore,selection);draft.requireCurrent();}
                catch(Exception changed){throw new IllegalStateException("The original prefix or selected device changed before completion.",changed);}
            };
            AndroidOrderedPathSelection.AppendCompletion proposal=draft.prepareAppendCompletion(current);
            current.run();
            EditText name=new EditText(this);name.setSingleLine(true);name.setHint("Profile name");
            choiceDialog("Use last "+AndroidOrderedPathSelection.finalModeTitle(draft.members().get(draft.members().size()-1).mode)+" node as final",proposal.description+"\n\nThe complete path keeps every draft node in order. Save it as a named future profile; Load and Connect remain separate choices.")
                    .setView(name).setPositiveButton("Save profile",(d,w)->{
                        try{
                            current.run();
                            AndroidConnectionProfileStore.Record saved=draft.saveAppendCompletion(proposal,name.getText().toString(),current);
                            statusView.setText("Saved "+saved.name+". Load it separately, then Connect to verify the complete path.");
                            refreshConnectionLater();
                        }catch(Exception changed){toast(safe(changed));}
                    }).setNegativeButton("Back",(d,w)->showOrderedEditor(draft)).show();
        }catch(Exception failed){toast(safe(failed));}
    }

    private void chooseOrderedPrefixStart(AndroidOrderedPathSelection draft) {
        try {
            if(mutationBusy())throw new IllegalStateException("Finish the current VPN operation before starting a prefix draft.");
            List<AndroidNodeStore.Node> choices=draft.prefixStartChoices();List<String> labels=new ArrayList<>();
            for(AndroidNodeStore.Node node:choices)labels.add(node.name);
            if(choices.isEmpty())throw new IllegalStateException("Add a paired WireGuard or AmneziaWG source before starting a prefix draft.");
            choiceDialog("Start an unfinished prefix","Choose the first real node. This replaces only the open editor draft; the saved connection remains unchanged.")
                    .setItems(labels.toArray(new CharSequence[0]),(d,w)->{
                        try {
                            String id=choices.get(w).id;List<String> modes=draft.prefixStartModes(id);List<String> titles=new ArrayList<>();
                            for(String mode:modes)titles.add(AndroidOrderedPathSelection.prefixModeTitle(mode));
                            choiceDialog("First prefix transport","Keep this node's exact saved transport and Start Layer.")
                                    .setItems(titles.toArray(new CharSequence[0]),(m,index)->{
                                        try{if(mutationBusy())throw new IllegalStateException("The VPN state changed before starting the draft.");draft.beginPrefix(id,modes.get(index));measureOrderedAppend(draft);}
                                        catch(Exception error){toast(safe(error));}
                                    }).setNegativeButton("Back",(m,index)->showOrderedEditor(draft)).show();
                        } catch(Exception error){toast(safe(error));}
                    }).setNegativeButton("Back",(d,w)->showOrderedEditor(draft)).show();
        } catch(Exception error){toast(safe(error));}
    }

    private void measureOrderedAppend(AndroidOrderedPathSelection draft) {
        try {
            if(mutationBusy())throw new IllegalStateException("Stop the current VPN before measuring the next node.");
            draft.requireCurrent();
            final long revision=draft.revision();
            List<AndroidNodeCandidateAppendSource.NextChoice> choices=AndroidNodeCandidateAppendSource.NEXT_CHOICES;List<String> labels=new ArrayList<>();
            for(var choice:choices)labels.add(choice.title());
            choiceDialog("Next transport","Measure saved candidates in this exact mode through the unfinished prefix. Applying a result adds one node after the last prefix.")
                    .setItems(labels.toArray(new CharSequence[0]),(d,w)->{
                        try {
                            startOrderedAppend(draft,choices.get(w),revision);
                        } catch(Exception error){toast(safe(error));}
                    }).setNegativeButton("Back",(d,w)->showOrderedEditor(draft)).show();
        } catch(Exception error){toast(safe(error));}
    }

    private void startOrderedAppend(AndroidOrderedPathSelection draft,AndroidNodeCandidateAppendSource.NextChoice choice,long revision)throws Exception {
        if(mutationBusy()||AndroidNodeCandidatePreparation.retained()!=null)
            throw new IllegalStateException("Finish the original VPN and candidate review before measuring the next prefix.");
        draft.requireCurrent();
        if(!draft.unfinished()||draft.revision()!=revision)
            throw new IllegalStateException("The unfinished prefix changed before its next measurement.");
        var capture=draft.candidateAppendCapture(choice.kind,choice.mode);int position=draft.members().size()-1;
        showOrderedEditor(draft);detachCandidatePreparation();
        preparedCandidateDialog=new AndroidNodeCandidatePreparationDialog(this,nodeStore,connection,this::refreshConnectionLater,this::continueOrderedDraft);
        preparedCandidateDialog.showDraft(capture,position,draft);
    }

    private void chooseOrderedExecution(AndroidOrderedPathSelection draft){
        try {
            if(mutationBusy())throw new IllegalStateException("Finish the current VPN operation before choosing execution.");
            draft.requireCurrent();
            choiceDialog("Ordered execution","For paths of up to eight nodes, Local, Server and Compare both support independently saved Shadowsocks 2022 nodes at any interior position between a paired WireGuard or AmneziaWG entry and a paired Shadowsocks 2022 final. Each imported node needs a literal IP address and Start Layer Off. A route with only paired packet hops can also use a paired Hysteria2 final.\n\n"
                    +"Use in draft inserts a measured paired Shadowsocks node after the chosen hop and keeps the remaining route in order. Longer Server and Compare paths with paired and imported Shadowsocks streams use one paired WireGuard, AWG2 Fast, or AWG2 Strong entry. Keep a literal import directly after the entry and a paired Shadowsocks final. Later intermediates can each be paired or imported. Keep every Start Layer Off. After Compare selects Local, each measured insertion keeps the original final. The request must fit the original lease limits.\n\n"
                    +"An imported exit requires a paired packet entry followed by at least two literal Shadowsocks 2022 imports. The entry can use AES or AES with XOR whitening. Server execution requires a matching registered route. Home DNS stays on the paired entry.\n\n"
                    +"A single SOCKS5, HTTP/HTTPS CONNECT or separately paired OpenVPN node goes immediately before the Shadowsocks final. A single Shadowsocks hostname can use that position after at least two paired hops with its saved Custom TCP resolver. A route starting with two imported Shadowsocks nodes requires Local execution.\n\n"
                    +"Compare both tests the same external endpoint through Local and Server, averages each path’s final-node and external HTTP response times, then verifies the winner. Failed paths receive no score.")
                    .setItems(new String[]{"Local","Server","Compare both"},(d,w)->{
                        try{if(mutationBusy())throw new IllegalStateException("The VPN state changed while choosing execution.");draft.setExecution(new String[]{"local","server","auto"}[w]);showOrderedEditor(draft);}
                        catch(Exception error){toast(safe(error));}
                    }).setNegativeButton("Back",(d,w)->showOrderedEditor(draft)).show();
        }catch(Exception error){toast(safe(error));}
    }

    private void chooseOrderedNode(AndroidOrderedPathSelection draft,boolean finalNode){
        try {
            if(mutationBusy())throw new IllegalStateException("Finish the current VPN operation before choosing another node.");
            AndroidOrderedCandidatePicker previous=orderedPicker;
            closeOrderedPicker();
            orderedPicker=new AndroidOrderedCandidatePicker(this,draft,finalNode,nodeStore,connection,telemetry,
                    (current,id)->{if(finalNode)chooseOrderedFinalMode(current,id);else chooseOrderedMode(current,id,-1);},
                    this::showOrderedEditor,this::refreshAll);
            orderedPicker.show(previous);
        } catch(Exception error) { closeOrderedPicker();toast(safe(error)); }
    }

    private void chooseOrderedFinalMode(AndroidOrderedPathSelection draft,String id){
        try {
            if(mutationBusy())throw new IllegalStateException("Finish the current VPN operation before choosing the final transport.");
            List<String> modes=draft.finalModes(id);List<String> labels=new ArrayList<>();
            for(String mode:modes)labels.add(AndroidOrderedPathSelection.finalModeTitle(mode));
            if(modes.isEmpty())throw new IllegalStateException("This original final node has no compatible complete transport.");
            if(modes.size()==1){draft.setFinal(id,modes.get(0));showOrderedEditor(draft);return;}
            choiceDialog("Final Router transport","Choose this node's exact saved transport. Hysteria2 keeps this node’s original Off, AES-256-GCM or AES-256-GCM plus XOR whitening choice; its own selected DNS and private credentials remain unchanged.")
                    .setItems(labels.toArray(new CharSequence[0]),(d,w)->{
                        try{if(mutationBusy())throw new IllegalStateException("The VPN state changed while choosing the final transport.");draft.setFinal(id,modes.get(w));showOrderedEditor(draft);}
                        catch(Exception error){toast(safe(error));}
                    }).setNegativeButton("Back",(d,w)->showOrderedEditor(draft)).show();
        } catch(Exception error){toast(safe(error));}
    }

    private void chooseOrderedMode(AndroidOrderedPathSelection draft,String id,int position){
        try {
            if(mutationBusy())throw new IllegalStateException("Finish the current VPN operation before choosing a transport.");
            List<String> modes=draft.prefixModes(id);List<String> labels=new ArrayList<>();
            for(String mode:modes)labels.add(AndroidOrderedPathSelection.prefixModeTitle(mode));
            if(modes.isEmpty())throw new IllegalStateException("This original node has no supported intermediate transport.");
            choiceDialog("Intermediate transport", "Choose this node's own saved transport. Its exact keys and Amnezia parameters stay attached when the node is moved.")
                    .setItems(labels.toArray(new CharSequence[0]),(d,w)->{
                        try{
                            if(mutationBusy())throw new IllegalStateException("The VPN state changed while choosing a transport.");
                            if(position<0)draft.addPrefix(id,modes.get(w));
                            else draft.setPrefixMode(position,modes.get(w));
                            if(position<0&&draft.canAddPrefix())chooseOrderedNode(draft,false);
                            else showOrderedEditor(draft);
                        }
                        catch(Exception error){toast(safe(error));}
                    }).setNegativeButton("Back",(d,w)->showOrderedEditor(draft)).show();
        } catch(Exception error) { toast(safe(error)); }
    }

    private void editOrderedPrefix(AndroidOrderedPathSelection draft,int position){
        List<String> actions=new ArrayList<>();List<Integer> destinations=new ArrayList<>();
        int firstEditable=draft.members().get(draft.members().size()-1).source.imported?1:0;
        if(position>firstEditable){actions.add("Move earlier");destinations.add(position-1);}
        if(position>=firstEditable){
            if(position<draft.members().size()-(draft.unfinished()?1:2)){actions.add("Move later");destinations.add(position+1);}
            actions.add("Remove this intermediate node");destinations.add(-1);
        }
        actions.add("Change transport");destinations.add(-2);
        if(draft.canMeasureThrough(position) || position==0 && draft.members().size()>=3 && draft.members().get(draft.members().size()-1).source.imported){actions.add("Measure candidates through this hop");destinations.add(-3);}
        new AlertDialog.Builder(this).setTitle("Hop "+(position+1)).setItems(actions.toArray(new CharSequence[0]),(d,w)->{
            try{if(mutationBusy())throw new IllegalStateException("The VPN state changed while editing the ordered path.");int target=destinations.get(w);
                if(target==-3){measureOrderedDraft(draft,position);return;}
                if(target==-2){chooseOrderedMode(draft,draft.members().get(position).source.id,position);return;}if(target<0)draft.removePrefix(position);else draft.movePrefix(position,target);showOrderedEditor(draft);}
            catch(Exception error){toast(safe(error));}
        }).setNegativeButton("Back",(d,w)->showOrderedEditor(draft)).show();
    }

    private void continueOrderedDraft(AndroidOrderedPathSelection draft,int inserted) {
        if(!resumed || isFinishing() || isDestroyed())return;
        try {
            draft.requireCurrent();
            var members=draft.members();
            if(draft.unfinished()) {
                if(inserted!=members.size()-1||!AndroidNodeCandidateAppendSource.supportsNextMode(members.get(inserted).mode))
                    throw new IllegalStateException("The measured append no longer ends this original prefix.");
                if(members.size()<AndroidNodeStore.PHYSICAL_TRAVERSAL_DEPTH) {
                    startOrderedAppend(draft,draft.appendContinuation(),draft.revision());
                    return;
                }
                showOrderedEditor(draft);return;
            }
            boolean canRetest=members.size()<AndroidNodeStore.PHYSICAL_TRAVERSAL_DEPTH || members.get(members.size()-1).source.imported;
            if(canRetest && draft.canMeasureThrough(inserted)) {
                measureOrderedDraft(draft,inserted);
                return;
            }
        } catch(Exception unavailable) { toast(safe(unavailable)); }
        showOrderedEditor(draft);
    }

    private void measureOrderedDraft(AndroidOrderedPathSelection draft,int position) throws Exception {
        java.util.concurrent.Callable<AndroidNodeStore.ChainCapture> capture=draft.candidateDraftCapture(position);
        showOrderedEditor(draft);
        detachCandidatePreparation();
        preparedCandidateDialog=new AndroidNodeCandidatePreparationDialog(this,nodeStore,connection,this::refreshConnectionLater,this::continueOrderedDraft);
        preparedCandidateDialog.showDraft(capture,position,draft);
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
                for(int i=0;i<presentation.members.size();i++){if(i>0)summary.append(" → ");AndroidOrderedPathPresentation.Member member=presentation.members.get(i);if(presentation.testing)summary.append(member.testing?"Testing ":"Saved ");summary.append(i+1).append(". ").append(member.name).append(" [").append(member.mode).append("]");if(member.httpResponseMs>0)summary.append(String.format(Locale.US,member.imported?" • Public path via custom node %.1f ms":" • HTTP proof %.1f ms",member.httpResponseMs));}
                multihopHint.setText(summary.append(" • ").append(presentation.executionLabel()).toString());
            }catch(Exception invalid){multihopHint.setText("The ordered path changed; reopen Edit hops.");}
            return;
        }
if(isExternalSelected()){boolean on=prefs().getBoolean(MULTI_ON,false);multihopToggle.setChecked(on);try{AndroidConnectionProfileStore.ExternalSelection path=new AndroidConnectionProfileStore(this,nodeStore,exitStore).currentExternalPath(prefs().getString(SELECTED_ID,""));multihopHint.setText(path.direct()?"Direct → "+path.exit.name:(path.ordinaryEntry!=null?path.ordinaryEntry.name:path.entry.name)+" → "+path.exit.name+" • "+path.entryMode+" → "+path.exit.protocol+" • "+("server".equals(path.execution)?"Server":"auto".equals(path.execution)?"Compare":"Local"));}catch(Exception invalid){multihopHint.setText("Choose external path in Edit hops");}return;}boolean live=connection.isMultihopConnected();boolean on=live||prefs().getBoolean(MULTI_ON,false);multihopToggle.setChecked(on);if(!on){multihopHint.setText("Off");return;}String entryId=live?connection.activeMultihopEntryId():prefs().getString(MULTI_ENTRY,""),exitId=live?connection.activeMultihopExitId():prefs().getString(MULTI_EXIT,""),mode=live?connection.activeMultihopExitMode():prefs().getString(MULTI_MODE,"");try{AndroidStandardExitStore.Entry ordinary=live?connection.activeImportedMultihopEntry():"external".equals(prefs().getString("multihop_entry_kind","router-vpn"))?exitStore.get(entryId):null;
        AndroidNodeStore.Node exit=nodeById(exitId);
        if(ordinary!=null){if(exit==null)throw new IllegalStateException("The final node is unavailable.");multihopHint.setText((live?"LIVE • ":"")+ordinary.name+" → "+exit.name+" • "+("wireguard".equals(ordinary.protocol)?"WireGuard":"amneziawg".equals(ordinary.protocol)?"AmneziaWG":"hysteria2".equals(ordinary.protocol)?"Hysteria2":"socks5".equals(ordinary.protocol)?"SOCKS5":"openvpn".equals(ordinary.protocol)?"OpenVPN":"http".equals(ordinary.protocol)?"HTTP CONNECT":"https".equals(ordinary.protocol)?"HTTPS CONNECT":"Shadowsocks 2022")+" → "+(switch(mode){case "hysteria2"->"Hysteria2";case "wg"->"WireGuard";case "awg2-fast"->"AmneziaWG Fast";case "awg2-strong"->"AmneziaWG Strong";case "shadowsocks"->"Shadowsocks";case "reality-vision"->"REALITY Vision";case "reality-pq-vision"->"PQ REALITY Vision";case "reality-xhttp"->"REALITY XHTTP";case "naive-h2"->"Naive HTTP/2";case "naive-h3"->"Naive HTTP/3";default->"Unsupported final transport";})+" • Local");return;}
        AndroidNodeStore.Node entry=nodeById(entryId);if(entry==null||exit==null){multihopHint.setText(live?"Live graph identity unavailable":"Choose hops");return;}StringBuilder s=new StringBuilder(live?"LIVE • ":"").append(entry.name);
        double entryTCP=live?0:telemetry.cachedMedian(entry.id),exitTCP=live?0:telemetry.cachedMedian(exit.id);
        if(entryTCP>0)s.append(String.format(Locale.US," • Direct TCP %.1f ms",entryTCP));
        s.append(" → ").append(exit.name);
        if(exitTCP>0)s.append(String.format(Locale.US," • Direct TCP %.1f ms",exitTCP));
        s.append(" • ").append(live?connection.activeMultihopEntryMode():prefs().getString("multihop_entry_mode","wg")).append(" → ").append(mode);multihopHint.setText(s.toString());}catch(Exception error){multihopHint.setText(live?"Live graph identity unavailable":"Choose hops");}}
    private AndroidNodeStore.Node nodeById(String id)throws Exception{if(id==null||id.isEmpty())return null;for(AndroidNodeStore.Node n:nodeStore.list())if(n.id.equals(id))return n;return null;}

    private boolean isExternalSelected(){return "external".equals(prefs().getString(SELECTED_KIND,"router-vpn"));}
    private boolean openSelectedExternal(boolean selectPath){
        AndroidUnifiedNodeCatalog.Item selected=selectedCatalogItem();if(selected==null||selected.isRouterVpn())return false;
        Intent intent=new Intent(this,StandardExitActivity.class);intent.putExtra(StandardExitActivity.EXTRA_EXIT_ID,selected.id);intent.putExtra(StandardExitActivity.EXTRA_SELECT_PATH,selectPath);startActivity(intent);return true;
    }

    private void showSettings(){if(openSelectedExternal(false))return;JSONObject p=activeRouterProfile();if(p==null){toast("Select a Router VPN node first.");return;}AndroidProfileSettingsDialog.show(this,nodeStore,this::refreshAll);}
    private void setQuickMultihop(boolean enabled) {
        if (mutationBusy()) {
            toast("Finish/disconnect the current VPN operation before changing multihop configuration.");
            refreshMultihopSummary();
            return;
        }
        if (enabled && isExternalSelected()) {
            configureMultihop();
            refreshMultihopSummary();
            return;
        }
        AndroidConnectionProfileStore.applySelection(prefs(), prefs().edit().putBoolean(MULTI_ON, enabled));
        refreshMap();
        refreshModeChoices();
        refreshConnectionState();
        refreshMultihopSummary();
        refreshTelemetry(true);
    }

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
    private void showMtuHelp(){
        try{
            AndroidDeviceMTU request=AndroidDeviceMTU.capture(this);
            String current=request.value==0?"Each connection uses its saved MTU policy.":"Device fixed MTU: "+request.value;
            choiceDialog("MTU",current).setItems(new String[]{"Current connection / Retest","Device MTU for all connections"},(d,w)->{
                if(w==0)AndroidMTUDialog.show(this);else AndroidDeviceMTUDialog.show(this);
            }).setNegativeButton("Close",null).show();
        }catch(Exception error){toast(safe(error));}
    }

    private void refreshForwardingState() { readForwardingState(false); }
    private void showForwarding() { readForwardingState(true); }

    private void readForwardingState(boolean showControls) {
        AndroidHomeStateStore.Snapshot home = AndroidHomeStateStore.snapshot(this);
        boolean measuring = AndroidViaEntryLatencyProbe.hasActiveOperation();
        if (measuring || !connection.isConnected() || !forwardingMaster.isCurrent(home)) {
            forwardButton.setText("Forward");
            if (showControls) {
                String reason = "Connect a Router VPN home-node path first to manage its forwarding master.";
                if (measuring) reason = "Via-entry candidate measurement is using a temporary tunnel. Wait for it to disconnect before managing forwarding.";
                else if (home.connected && "external".equals(home.logicalMode))
                    reason = "A direct external exit has no Router VPN home-node forwarding policy. Connect a Router VPN home-node path first.";
                dialog("Master port forwarding", reason);
            }
            return;
        }
        if (forwardingBusy) {
            if (showControls) toast("Forwarding master state is already being verified.");
            return;
        }
        forwardingBusy = true;
        forwardButton.setText("Forward …");
        forwardingMaster.get(home, (verified, error) -> runOnUiThread(() -> {
            forwardingBusy = false;
            if (!resumed || isFinishing() || isDestroyed()) return;
            if (!forwardingMaster.isCurrent(home) || verified != null && !forwardingMaster.isCurrent(verified)) {
                forwardButton.setText("Forward");
                return;
            }
            if (error != null || verified == null) {
                forwardButton.setText("Forward ?");
                if (showControls) dialog("Master port forwarding", "Could not verify the forwarding master. " + safe(error));
                return;
            }
            forwardButton.setText(verified.enabled ? "Forward ON" : "Forward OFF");
            if (showControls) new AlertDialog.Builder(this)
                    .setTitle("Master port forwarding • " + (verified.enabled ? "ON" : "OFF"))
                    .setMessage("This changes existing WAN→tunnel forwarding rules and Protected DMZ on the active Router VPN home node. The Setup Center admin token never leaves the server.")
                    .setPositiveButton(verified.enabled ? "Turn OFF" : "Turn ON", (d, w) -> setForwardingMaster(verified))
                    .setNeutralButton("Rules in Setup Center", (d, w) -> dialog("Forwarding rules", "Manage individual rules and Protected DMZ in Setup Center."))
                    .setNegativeButton("Close", null).show();
        }));
    }

    private void setForwardingMaster(AndroidForwardingMaster.Verified displayed) {
        if (forwardingBusy || !resumed || isFinishing() || isDestroyed()) return;
        if (!forwardingMaster.isCurrent(displayed)) {
            forwardButton.setText("Forward");
            dialog("Master port forwarding", "The connection changed. Refresh forwarding and confirm again.");
            return;
        }
        forwardingBusy = true;
        forwardButton.setText("Forward …");
        forwardingMaster.set(displayed, (verified, error) -> runOnUiThread(() -> {
            forwardingBusy = false;
            if (!resumed || isFinishing() || isDestroyed()) return;
            if (!forwardingMaster.isCurrent(displayed)) { forwardButton.setText("Forward"); return; }
            if (error != null || verified == null) {
                forwardButton.setText("Forward ?");
                dialog("Forwarding update failed", safe(error));
                return;
            }
            forwardButton.setText(verified.enabled ? "Forward ON" : "Forward OFF");
            toast("Server port-forwarding master is now " + (verified.enabled ? "ON" : "OFF") + ".");
        }));
    }

    private void selectHomeDns(int position){
        if(displayedDnsIndex<0||position==displayedDnsIndex||position!=dnsSpinner.getSelectedItemPosition()||isExternalSelected())return;
        // Keep the saved choice visible while an editor or an unsuccessful request is pending.
        dnsSpinner.setSelection(displayedDnsIndex,false);
        if(mutationBusy()){toast("Disconnect/finish the current VPN operation before changing DNS.");return;}
        String mode=DNS_MODES[position];
        if("home".equals(mode)||"fastest".equals(mode)||"rescue".equals(mode))setQuickDns(mode);
        else AndroidProductParity.showDNS(this,nodeStore,mode,this::refreshDnsSelection);
    }

    private void setQuickDns(String mode){
        if(openSelectedExternal(false)){refreshDnsSelection();return;}
        if(mutationBusy()){toast("Disconnect/finish before changing DNS.");refreshDnsSelection();return;}
        try{
            AndroidNodeStore.SelectionSnapshot source=nodeStore.snapshotSelection();
            if(source.activeBundle==null)throw new IllegalStateException("Select a Router VPN node first.");
            JSONObject root=new JSONObject(new String(source.activeBundle,StandardCharsets.UTF_8)),p=selectedProfile(root);
            if(p==null)throw new IllegalStateException("Select a Router VPN node first.");
            if("fastest".equals(mode)&&p.optString("fastest_dns_host","").trim().isEmpty()){
                AndroidProductParity.showDNS(this,nodeStore,mode,this::refreshDnsSelection);
                return;
            }
            AndroidProductParity.selectQuickDNS(p,mode);
            nodeStore.applySettings(source,root.toString().getBytes(StandardCharsets.UTF_8));
            toast("DNS set to "+mode+" for the next tunnel; runtime proof still required.");
        }catch(Exception error){toast(safe(error));}
        refreshDnsSelection();
    }

    private void refreshDnsSelection(){JSONObject p=activeRouterProfile();if(isExternalSelected()){try{AndroidStandardExitStore.Entry exit=exitStore.get(prefs().getString(SELECTED_ID,""));p=AndroidTorProfile.isTor(exit.protocol)?exit.torPolicy:exit.policy;if(p==null)p=new JSONObject();}catch(Exception invalid){dnsHint.setText("Saved external DNS unavailable; check Settings before connecting.");return;}dnsHint.setText("Saved external DNS; Details opens its complete policy. Connected requires the captured path and DNS proof.");}else dnsHint.setText("DNS changes the next tunnel resolver path; Connected still requires runtime DNS/path proof.");String mode=p==null?"home":p.optString("dns_mode","home").trim().toLowerCase(Locale.US);int index=0;for(int i=0;i<DNS_MODES.length;i++)if(DNS_MODES[i].equals(mode)){index=i;break;}displayedDnsIndex=index;dnsSpinner.setSelection(index,false);}

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
        // Historical over-capacity lists can still delete a chosen row. Save checks the resulting count.
        for (int i = 0; i < rows.length(); i++) {
            JSONObject row = rows.getJSONObject(i);
            if (row.getString("name").trim().isEmpty()) throw new IllegalStateException("Existing CUSTOM preset name is invalid.");
            JSONArray layers = row.getJSONArray("layers");
            if (layers.length() == 0 || layers.length() > 128) throw new IllegalStateException("Existing CUSTOM layers are invalid.");
            for (int n = 0; n < layers.length(); n++) if (layers.getString(n).trim().isEmpty()) throw new IllegalStateException("Existing CUSTOM layer is invalid.");
        }
        return rows;
    }

    private void saveCustomPreset(CustomPreset preset, CustomPreset editing) throws Exception {
        AndroidCustomPresetCommit.Snapshot before = AndroidCustomPresetCommit.snapshot(prefs());
        JSONArray rows = checkedCustomRows(before.presets), next = new JSONArray();
        boolean found = false;
        for (int i = 0; i < rows.length(); i++) {
            JSONObject row = rows.getJSONObject(i);
            String name = row.getString("name");
            if (editing != null && name.equals(editing.name)) {
                if (found || !row.getJSONArray("layers").toString().equals(new JSONArray(editing.layers).toString()))
                    throw new IllegalStateException("The selected CUSTOM preset changed. Reopen it before saving.");
                found = true;
            } else {
                if ((editing == null || !preset.name.equals(editing.name)) && name.equalsIgnoreCase(preset.name))
                    throw new IllegalStateException("A CUSTOM preset already uses that name. Edit that preset or choose a different name.");
                next.put(row);
            }
        }
        if (editing != null && !found) throw new IllegalStateException("The selected CUSTOM preset was removed. Reopen the list.");
        if (next.length() >= AndroidCustomPresetCommit.MAX_PRESETS) throw new IllegalStateException("CUSTOM preset limit reached.");
        JSONObject row = new JSONObject(); row.put("name", preset.name); row.put("layers", new JSONArray(preset.layers)); next.put(row);
        AndroidCustomPresetCommit.publish(before, next.toString(), "custom:" + preset.name, () -> !mutationBusy());
    }

    private void deleteCustomPreset(CustomPreset editing) throws Exception {
        AndroidCustomPresetCommit.Snapshot before = AndroidCustomPresetCommit.snapshot(prefs());
        JSONArray rows = checkedCustomRows(before.presets), next = new JSONArray(); boolean found = false;
        for (int i = 0; i < rows.length(); i++) {
            JSONObject row = rows.getJSONObject(i);
            if (row.getString("name").equals(editing.name)) {
                if (found || !row.getJSONArray("layers").toString().equals(new JSONArray(editing.layers).toString()))
                    throw new IllegalStateException("The selected CUSTOM preset changed. Reopen it before deleting.");
                found = true;
            } else next.put(row);
        }
        if (!found) throw new IllegalStateException("CUSTOM preset disappeared; reopen the list.");
        String mode = before.mode.equals("custom:" + editing.name) ? "smart-auto" : before.mode;
        AndroidCustomPresetCommit.publish(before, next.toString(), mode, () -> !mutationBusy());
    }

    // AOSP AlertController gives a message priority over its item list. Put the
    // explanation in a custom title so every action remains visible/clickable.
    private AlertDialog.Builder choiceDialog(String title,String explanation){
        AlertDialog.Builder builder=new AlertDialog.Builder(this);
        android.content.Context theme=builder.getContext();
        LinearLayout header=new LinearLayout(theme);header.setOrientation(LinearLayout.VERTICAL);
        header.setPadding(dp(24),dp(18),dp(24),dp(8));
        TextView heading=new TextView(theme);heading.setText(title);heading.setTextSize(18);
        heading.setTypeface(heading.getTypeface(),Typeface.BOLD);header.addView(heading);
        TextView note=new TextView(theme);note.setText(explanation);note.setTextSize(12);
        note.setPadding(0,dp(8),0,0);header.addView(note);
        return builder.setCustomTitle(header);
    }
    private void dialog(String title,String message){new AlertDialog.Builder(this).setTitle(title).setMessage(message).setPositiveButton("OK",null).show();}
    private SharedPreferences prefs(){return getSharedPreferences(PREFS,MODE_PRIVATE);}
    private Spinner homeSpinner(){
        Spinner spinner=new Spinner(new ContextThemeWrapper(this,android.R.style.Theme_Material),Spinner.MODE_DROPDOWN);
        spinner.setPopupBackgroundDrawable(round(Color.rgb(29,43,68),12));
        spinner.setDropDownWidth(ViewGroup.LayoutParams.MATCH_PARENT);
        return spinner;
    }
    private <T> ArrayAdapter<T> homeChoices(Spinner spinner,List<T> choices){
        ArrayAdapter<T> adapter=new ArrayAdapter<T>(spinner.getContext(),android.R.layout.simple_spinner_item,choices){
            private TextView readableLabel(View view){
                TextView label=(TextView)view;
                label.setSingleLine(false);
                label.setEllipsize(null);
                label.setTextColor(Color.WHITE);
                return label;
            }
            @Override public View getView(int position,View recycled,ViewGroup parent){
                return readableLabel(super.getView(position,recycled,parent));
            }
            @Override public View getDropDownView(int position,View recycled,ViewGroup parent){
                HomeChoiceRow row=recycled instanceof HomeChoiceRow
                        ?(HomeChoiceRow)recycled:new HomeChoiceRow(spinner.getContext());
                row.label.setText(String.valueOf(getItem(position)));
                return row;
            }
        };
        return adapter;
    }
    /** The popup forces scrolling on root TextViews; keep the label inside a checkable row. */
    private final class HomeChoiceRow extends LinearLayout implements android.widget.Checkable {
        final android.widget.CheckedTextView label;
        HomeChoiceRow(android.content.Context context){
            super(context);
            setOrientation(LinearLayout.VERTICAL);
            setLayoutParams(new android.widget.AbsListView.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT,ViewGroup.LayoutParams.WRAP_CONTENT));
            label=new android.widget.CheckedTextView(context,null,android.R.attr.spinnerDropDownItemStyle);
            label.setId(android.R.id.text1);
            label.setTextColor(Color.WHITE);
            label.setSingleLine(false);
            label.setEllipsize(null);
            label.setMinimumHeight(dp(48));
            label.setPaddingRelative(dp(8),dp(8),dp(8),dp(8));
            addView(label,new LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT,ViewGroup.LayoutParams.WRAP_CONTENT));
        }
        @Override public void setChecked(boolean checked){label.setChecked(checked);}
        @Override public boolean isChecked(){return label.isChecked();}
        @Override public void toggle(){label.toggle();}
    }
    private LinearLayout row(){return new AndroidControlRow(this);}
    private LinearLayout controlRow(String title){LinearLayout r=row();TextView label=text(title,13,true);label.setTextColor(Color.WHITE);label.setGravity(Gravity.END);label.setMinimumWidth(dp(72));r.addView(label);return r;}
    private TextView text(String value,int sp,boolean bold){TextView v=new TextView(this);v.setText(value);v.setTextSize(sp);v.setTextColor(Color.WHITE);if(bold)v.setTypeface(v.getTypeface(),Typeface.BOLD);return v;}
    private Button primaryButton(String value){Button b=smallButton(value);b.setTextSize(17);b.setTypeface(b.getTypeface(),Typeface.BOLD);b.setTextColor(Color.WHITE);b.setBackgroundTintList(ColorStateList.valueOf(Color.rgb(95,78,220)));return b;}
    private Button smallButton(String value){Button b=new Button(this);b.setText(value);b.setAllCaps(false);b.setTextColor(Color.WHITE);b.setTextSize(11);b.setMinWidth(0);b.setMinimumWidth(0);b.setPadding(dp(7),0,dp(7),0);b.setBackgroundTintList(ColorStateList.valueOf(Color.rgb(39,55,82)));return b;}
    private GradientDrawable round(int color,int radius){GradientDrawable d=new GradientDrawable();d.setColor(color);d.setCornerRadius(dp(radius));return d;}
    private LinearLayout.LayoutParams margins(int l,int t,int r,int b){LinearLayout.LayoutParams p=new LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT,LinearLayout.LayoutParams.WRAP_CONTENT);p.setMargins(l,t,r,b);return p;}
    private int dp(float value){return Math.round(value*getResources().getDisplayMetrics().density);}
    private static String safe(Throwable error){String value=error==null?"":error.getMessage();return value==null||value.trim().isEmpty()?"Router VPN error":value.trim();}
    private void toast(String message){Toast.makeText(this,message==null?"Router VPN":message,Toast.LENGTH_LONG).show();}
}
