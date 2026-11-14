#!/usr/bin/env python3
"""Execute ProductActivity's choice handlers at Android's dialog API boundary.

The selected shipping Java methods are compiled unchanged. The Android widget
double models AOSP AlertController.setupContent: setMessage suppresses setItems.
Storage, telemetry and VPN handles are bounded doubles; this is not device UI QA.
Each former broken builder is restored independently as a negative control.
"""
from pathlib import Path
import importlib.util
import os
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
JAVA = ROOT / "android/app/src/main/java/com/eabusham/routervpn"
JSON_JAR = os.environ.get("ANDROID_JSON_JAR", "/usr/share/java/com.android.json.jar")
SOURCE = (JAVA / "ProductActivity.java").read_text()
spec = importlib.util.spec_from_file_location("product_dialog_widgets", ROOT / "android/test_android_tor_form.py")
W = importlib.util.module_from_spec(spec)
spec.loader.exec_module(W)

SIGNATURES = (
    "void runRouterNodeComparison(", "void showPerformance(", "void showNodes(",
    "void showProfileManager(",
    "void chooseMultihopExecution(AndroidNodeStore.Node entry,AndroidNodeStore.Node exit,String mode,String entryMode,AndroidViaEntryLatencyProbe.Result selection)",
    "void configurePairMultihop(", "void showViaEntryExitPicker(", "void configureMultihop(",
)


def method(signature):
    start = SOURCE.index("    private " + signature)
    end = SOURCE.index("\n    private ", start + 10)
    return SOURCE[start:end]


def block(source, signature):
    start = source.index(signature)
    end = source.index("{", start) + 1
    depth = 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[start:end]


BOUNDARIES = r'''package com.eabusham.routervpn;
import java.util.*;import java.security.MessageDigest;import java.nio.charset.StandardCharsets;import org.json.JSONObject;import android.util.Base64;
final class MemoryPreferences implements android.content.SharedPreferences {
 final Map<String,Object> values=new LinkedHashMap<>();int writes;
 public String getString(String key,String fallback){return (String)values.getOrDefault(key,fallback);}
 public Map<String,?> getAll(){return new LinkedHashMap<>(values);}
 public Editor edit(){return new Editor(){final Map<String,Object> next=new LinkedHashMap<>();
  public Editor putString(String key,String value){next.put(key,value);return this;}
  public Editor putBoolean(String key,boolean value){next.put(key,value);return this;}
  public void apply(){writes++;values.putAll(next);}
 };}
}
final class AndroidNodeStore {
 static final class Node {final String id,name;Node(String id){this.id=id;name="Node "+id;}}
 final List<Node> nodes=new ArrayList<>(Arrays.asList(new Node("a"),new Node("b"),new Node("c")));
 String selected="a",identityFault="";int selections,catalogCaptures;boolean staleCatalog;Runnable duringCapture;
 List<Node> list(){return nodes;}String activeId(){return selected;}
 void select(String id){selected=id;selections++;}
 static final class ChainSource {
  final String id,profileId,proofId;final String original;final boolean imported=false;
  ChainSource(String id,String fault)throws Exception{
   this.id=id;profileId=id;byte[] key=new byte[32];Arrays.fill(key,(byte)id.charAt(0));
   String config="[Peer]\nPublicKey="+java.util.Base64.getEncoder().encodeToString(key)+"\n";
   JSONObject assets=new JSONObject().put("shadowsocks",new JSONObject().put("sing-box.json","original captured asset"))
    .put("wg",new JSONObject().put("wg.conf",java.util.Base64.getEncoder().encodeToString(config.getBytes(StandardCharsets.UTF_8))));
   JSONObject source=new JSONObject().put("profiles",assets).put("selectedRouterID",id).put("routerProfiles",new org.json.JSONArray().put(new JSONObject().put("id",id)));
   proofId=stableNodeIdentity(source);source.put("nodeProofId",proofId);
   if(fault.equals("missing-wg"))assets.remove("wg");
   if(fault.equals("short-key"))assets.getJSONObject("wg").put("wg.conf",java.util.Base64.getEncoder().encodeToString("[Peer]\nPublicKey=AQ==\n".getBytes(StandardCharsets.UTF_8)));
   if(fault.equals("wrong-proof"))source.put("nodeProofId","0".repeat(64));
   original=source.toString();
  }
  JSONObject bundle()throws Exception{return new JSONObject(original);}
  JSONObject profile()throws Exception{return selectedProfile(bundle());}
  // SHIPPING_PAIRED_IDENTITY
 }
 // SHIPPING_NODE_IDENTITY_HELPERS
 static final class ChainCapture {final List<ChainSource> members;final List<String> modes;ChainCapture(List<ChainSource>s,List<String>m){members=s;modes=m;}}
 static final class ChainCatalog {
  final AndroidNodeStore owner;final String selectedId;final List<Node> nodes;
  ChainCatalog(AndroidNodeStore owner){this.owner=owner;selectedId=owner.selected;nodes=Collections.unmodifiableList(new ArrayList<>(owner.nodes));}
  ChainSource source(String id)throws Exception{for(Node node:nodes)if(node.id.equals(id))return new ChainSource(id,owner.identityFault);throw new IllegalStateException("captured catalog has no original node");}
  void requireCurrent(){if(owner.staleCatalog||!selectedId.equals(owner.selected))throw new IllegalStateException("original ordered catalog changed");}
 }
 ChainCatalog captureChainCatalog(){catalogCaptures++;ChainCatalog capture=new ChainCatalog(this);if(duringCapture!=null)duringCapture.run();return capture;}
}
final class AndroidVpnMutationGuard {static boolean isBusy(android.content.Context context){return ((ProductDialogHarness)context).busy;}}

final class AndroidStandardExitStore {
 static final class Entry {final String id,name,protocol;Entry(String id){this(id,"shadowsocks");}Entry(String id,String protocol){this.id=id;name="Imported "+id;this.protocol=protocol;}}
 final List<Entry> entries=new ArrayList<>();List<Entry> list(){return entries;}
}
final class AndroidUnifiedNodeCatalog {
 static final String SORT_CURRENT="current";
 static final class Item {
  final String id,name;String location="";final boolean router;boolean usageAvailable=true;int useCount;Item(String id,boolean router){this.id=id;this.name="Catalog "+id;this.router=router;}
  boolean isRouterVpn(){return router;}boolean hasCoordinates(){return router;}Double latencyMedianMs;boolean hasMeasuredLatency(){return latencyMedianMs!=null;}
 }
 final List<Item> items=new ArrayList<>(Arrays.asList(new Item("a",true),new Item("external",false)));
 List<Item> list(String order){return items;}
}
final class AndroidTelemetry {
 static class Result {
  final String id,name;final double minMs,medianMs,averageMs,trimmedMeanMs,p90Ms,maxMs;final int samples,failed;final String proof="routed proof";
  Result(String id,double ms){this(id,ms,ms,50,0);}
  Result(String id,double median,double trimmed,int samples,int failed){this.id=id;name="Measured "+id;medianMs=median;trimmedMeanMs=trimmed;minMs=Math.min(median,trimmed);maxMs=p90Ms=Math.max(median,trimmed);averageMs=trimmed;this.samples=samples;this.failed=failed;}
  boolean stale;void requireCurrent(){if(stale)throw new IllegalStateException("Measured source changed; Retest.");}String shortLabel(){return medianMs+" ms";}String detail(){return "detail "+id;}
 }
 static final class PathResult extends Result {PathResult(){super("current",3);}}
 interface One{void result(Result value,Throwable error);}interface Many{void result(List<Result> values,Throwable error);}
 interface PathOne{void result(PathResult value,Throwable error);}final PathResult path=new PathResult();PathOne pending;boolean delayPath;
 final List<Result> results=Arrays.asList(new Result("b",3),new Result("a",8),new Result("c",12));
 Many pendingFastest;boolean delayFastest;int fastestCancels;
 int allSamples,nodeSamples,currentSamples,currentCalls,speedBytes;String measuredNode="";
 double cachedMedian(String id){return id.equals("a")?7:0;}
 void measureFastest(Many callback){allSamples=50;if(delayFastest)pendingFastest=callback;else callback.result(results,null);}
 void cancelFastest(){fastestCancels++;for(Result r:results)r.stale=true;}
 void measureAll(int count,Many callback){allSamples=count;callback.result(results,null);}
 void measureNode(AndroidNodeStore.Node node,int count,One callback){measuredNode=node.id;nodeSamples=count;callback.result(results.get(0),null);}
 void currentPath(int count,PathOne callback){currentSamples=count;currentCalls++;if(delayPath)pending=callback;else callback.result(path,null);}
 void speedTest(int bytes,One callback){speedBytes=bytes;callback.result(results.get(0),null);}
}
final class Connection {boolean connected=true;boolean isConnected(){return connected;}}
final class AndroidHomeStateStore {static class Snapshot{String logicalMode="raw-tunnel",activeExternalId="external";}static Snapshot state=new Snapshot();static Snapshot snapshot(android.content.Context context){return state;}}
final class AndroidExternalLiveTelemetry {
 static final class Result {String id="external";double medianMs=6;boolean stale;void requireCurrent(){if(stale)throw new IllegalStateException("stale native HTTPS receipt");}String detail(){return "3 HTTPS responses after routed TLS; separate from ICMP";}}
 interface Callback{void finished(Result result,Throwable error);}final Result result=new Result();Callback pending;boolean delay,running;int calls,cancels;
 boolean isRunning(){return running;}void measure(String id,Callback cb){calls++;if(delay){running=true;pending=cb;}else cb.finished(result,null);}void cancel(){cancels++;result.stale=true;}
}
final class AndroidExternalNodeComparison {static boolean hasActiveOperation(){return false;}}
final class AndroidMTUMeasurementGate {static boolean busy;static boolean held(){return busy;}}
final class AndroidViaEntryLatencyProbe {
 static boolean hasActiveOperation(){return false;}
 static final class Result {
  final AndroidNodeStore.Node entry;final List<AndroidNodeStore.Node> candidates;final List<AndroidTelemetry.Result> values;
  boolean stale;
  Result(AndroidNodeStore.Node entry,List<AndroidNodeStore.Node> candidates,List<AndroidTelemetry.Result> values){this.entry=entry;this.candidates=candidates;this.values=values;}
  void requireCurrent(){if(stale)throw new IllegalStateException("Captured decision changed; Retest.");}
  AndroidTelemetry.Result measurement(String id){for(var value:values)if(value.id.equals(id))return value;return null;}
  // SHIPPING_VIA_RANKING
 }
}
'''

HARNESS_PREFIX = r'''package com.eabusham.routervpn;
import android.app.AlertDialog;import android.content.SharedPreferences;import android.graphics.Color;import android.graphics.Typeface;
import android.widget.*;import org.json.JSONObject;import java.util.*;
public final class ProductDialogHarness extends android.app.Activity {
 static final String SELECTED_KIND="selected_kind",SELECTED_ID="selected_id",MULTI_ON="multihop_on",MULTI_ENTRY="multihop_entry",MULTI_EXIT="multihop_exit",MULTI_MODE="multihop_mode";
 final MemoryPreferences saved=new MemoryPreferences();final AndroidNodeStore nodeStore=new AndroidNodeStore();final AndroidStandardExitStore exitStore=new AndroidStandardExitStore();
 AndroidStandardExitStore.Entry importedEntry;List<AndroidNodeStore.Node> importedFinals;
 final AndroidUnifiedNodeCatalog catalog=new AndroidUnifiedNodeCatalog();final AndroidTelemetry telemetry=new AndroidTelemetry();
 final Connection connection=new Connection();final Button fastestButton=new Button(this);final CheckBox multihopToggle=new CheckBox(this);
 final TextView liveLatency=new TextView(this);AndroidTelemetry.PathResult currentPathReceipt;AndroidExternalLiveTelemetry.Result currentExternalReceipt;final AndroidExternalLiveTelemetry externalTelemetry=new AndroidExternalLiveTelemetry();boolean resumed=true,telemetryBusy;long lastTelemetryAt,telemetryGeneration;double currentPathMs;
 AlertDialog fastestProgressDialog;AndroidOrderedPathSelection ordered;
 public android.content.SharedPreferences getSharedPreferences(String name,int mode){return saved;}
 void showOrderedEditor(AndroidOrderedPathSelection draft){ordered=draft;} // Explicit editor-presentation sink; constructor and capture checks are shipping code.
 boolean busy;String selected="",profile="",pair="",entry="",exit="",message="",infoTitle="",info="";int candidateTimes,routed,refreshes,externalBenchmarks,externalComparisons;boolean externalComparisonAdopt;
 SharedPreferences prefs(){return saved;}boolean mutationBusy(){return busy;}void toast(String text){message=text;}
 void refreshNodes(){}void refreshAll(){refreshes++;}void refreshMap(){}void dialog(String title,String text){infoTitle=title;info=text;}
 public boolean isDestroyed(){return false;}void showNodeSort(){pair="sort";}void showSavedStatistics(){infoTitle="Saved statistics";}void runCurrentSpeed(){if(!connection.isConnected()){toast("Connect first");return;}telemetry.speedTest(8<<20,(r,e)->dialog("Real VPN path speed",r.detail()));}void showAddRouter(){showPairDialog();}void showPairDialog(){pair="router";}void openStandardExits(){pair="external";}
 boolean isExternalSelected(){return "external".equals(saved.getString(SELECTED_KIND,"router-vpn"));}void runExternalBenchmark(){externalBenchmarks++;}
 void showExternalComparison(boolean connectFastest){externalComparisons++;externalComparisonAdopt=connectFastest;}
 boolean openSelectedExternal(boolean selectPath){return false;}
 void selectCatalog(AndroidUnifiedNodeCatalog.Item item){selected=item.id;}
 void showProfileActions(AndroidNodeStore.Node node){profile=node.id;}
 AndroidNodeStore.Node nodeById(String id){for(AndroidNodeStore.Node n:nodeStore.nodes)if(n.id.equals(id))return n;return null;}
 JSONObject activeRouterProfile(){return new JSONObject();}void runRoutedHopSpeeds(){routed++;}void runCandidateTimes(){candidateTimes++;}
 void refreshMultihopSummary(){}
 void prepareViaEntryExitMeasurement(AndroidNodeStore.Node node,List<AndroidNodeStore.Node> nodes){entry=node.id;exit=Integer.toString(nodes.size());}
 void chooseImportedRouterFinal(AndroidStandardExitStore.Entry first,List<AndroidNodeStore.Node> finals){importedEntry=first;importedFinals=finals;}
 void chooseMultihopMode(AndroidNodeStore.Node first,AndroidNodeStore.Node last,AndroidViaEntryLatencyProbe.Result result){entry=first.id;exit=last.id;}
 AndroidViaEntryLatencyProbe.Result capture(){return new AndroidViaEntryLatencyProbe.Result(nodeById("a"),Arrays.asList(nodeById("b"),nodeById("c")),Collections.emptyList());}
 static String safe(Throwable error){return error==null?"error":error.getMessage();}
'''

HARNESS_SUFFIX = r'''
 static int checks;
 static void check(boolean value,String label){checks++;if(!value)throw new AssertionError(label);}
 static AlertDialog shown(int count,String title){
  AlertDialog value=AlertDialog.last;check(value!=null&&value.itemsVisible(),title+" items must be reachable under AOSP message/list semantics");
  check(value.items.length==count,title+" item count");check(value.message==null,title+" must not suppress list with message");
  check(value.customTitle instanceof LinearLayout,title+" retains accessible explanatory header");
  LinearLayout header=(LinearLayout)value.customTitle;
  check(header.children.size()==2&&((TextView)header.children.get(0)).getText().toString().contains(title),title+" visible title");
  check(((TextView)header.children.get(1)).getText().length()>20,title+" explanation retained");return value;
 }
 static void fastest(){
  ProductDialogHarness held=new ProductDialogHarness();held.telemetry.delayFastest=true;held.showRouterFastConnectMenu();
  AlertDialog progress=AlertDialog.last;check(progress.showing&&!progress.cancelable,"Fastest progress owns its visible cancellation until drain");
  progress.getButton(AlertDialog.BUTTON_NEGATIVE).performClick();
  check(held.telemetry.fastestCancels==1&&progress.showing&&held.fastestProgressDialog==progress,"Cancel retains original progress before worker drain");
  held.telemetry.pendingFastest.result(null,new IllegalStateException("cancelled after drain"));
  check(!progress.showing&&held.fastestProgressDialog==null&&held.nodeStore.selections==0,"drained cancellation cannot select a node");
  ProductDialogHarness closed=new ProductDialogHarness();closed.telemetry.delayFastest=true;closed.showRouterFastConnectMenu();AlertDialog parent=AlertDialog.last;parent.dismiss();
  check(closed.telemetry.fastestCancels==1&&closed.fastestProgressDialog==parent,"parent Close retains the cancelling batch until drain");
  closed.telemetry.pendingFastest.result(null,new IllegalStateException("cancelled after parent close"));
  check(closed.fastestProgressDialog==null&&closed.nodeStore.selections==0,"parent Close cannot publish a winner");
  ProductDialogHarness h=new ProductDialogHarness();h.showRouterFastConnectMenu();AlertDialog d=shown(4,"Select node");d.clickItem(0);
  check(h.telemetry.allSamples==50&&h.nodeStore.selected.equals("b")&&h.saved.getString(SELECTED_ID,"").equals("b"),"Fastest chooses measured first node");
  check(h.message.contains("Press Connect"),"Fastest selects without connecting");
  h=new ProductDialogHarness();h.showRouterFastConnectMenu();d=shown(4,"Select node");d.clickItem(2);check(h.nodeStore.selected.equals("a"),"specific Fastest list choice exact");
  h=new ProductDialogHarness();h.showRouterFastConnectMenu();d=shown(4,"Select node");h.busy=true;d.clickItem(0);check(h.nodeStore.selections==0&&h.saved.writes==0,"late busy prevents Fastest mutation");
  h=new ProductDialogHarness();h.busy=true;h.showRouterFastConnectMenu();check(h.telemetry.allSamples==0,"initial busy avoids measurement");
  h=new ProductDialogHarness();h.showRouterFastConnectMenu();d=shown(4,"Select node");h.telemetry.results.get(0).stale=true;d.clickItem(0);check(h.nodeStore.selections==0&&h.saved.writes==0,"stale measured source cannot be selected");
 }
 static void performance(){
  for(boolean close:new boolean[]{false,true}){
   ProductDialogHarness held=new ProductDialogHarness();held.telemetry.delayFastest=true;held.showPerformance();shown(10,"Performance").clickItem(2);AlertDialog progress=AlertDialog.last;
   check(held.telemetry.allSamples==50&&progress.showing,"Performance comparison uses owned fifty-sample progress");
   if(close)progress.dismiss();else progress.getButton(AlertDialog.BUTTON_NEGATIVE).performClick();
   check(held.telemetry.fastestCancels==1&&held.fastestProgressDialog==progress,"Performance cancellation retains original batch until drain");
   held.telemetry.pendingFastest.result(null,new IllegalStateException("drained cancellation"));
   check(held.fastestProgressDialog==null&&held.nodeStore.selections==0&&held.saved.writes==0,"Performance cancellation cannot select a node");
  }
  ProductDialogHarness compared=new ProductDialogHarness();compared.showPerformance();shown(10,"Performance").clickItem(2);
  check(compared.infoTitle.equals("50-sample Router comparison")&&compared.info.contains("10% trimmed mean")&&compared.nodeStore.selections==0&&compared.saved.writes==0,"compare-only displays complete statistics without winner adoption");
  ProductDialogHarness selected=new ProductDialogHarness();selected.saved.values.put(SELECTED_KIND,"external");selected.saved.values.put(SELECTED_ID,"provider-only");selected.showPerformance();shown(10,"Performance").clickItem(1);check(selected.externalBenchmarks==1&&selected.telemetry.nodeSamples==0,"selected external benchmark fell back to the active Router node");
  for(int action=0;action<10;action++){
   ProductDialogHarness h=new ProductDialogHarness();h.showPerformance();AlertDialog d=shown(10,"Performance");d.clickItem(action);
   switch(action){case 0:check(h.telemetry.currentSamples==5,"current path actual callback");break;
    case 1:check(h.telemetry.nodeSamples==50&&h.telemetry.measuredNode.equals("a"),"durable 50-sample selected node");break;
    case 2:check(h.telemetry.allSamples==50,"all-node callback");break;
    case 3:check(h.telemetry.speedBytes==8<<20,"real transfer requested8MiB");break;
    case 4:check(h.routed==1,"native routed hop speed action");break;
    case 6:check(h.infoTitle.equals("Saved statistics"),"saved durable statistics action");break;
    case 7:check(h.externalComparisons==1&&!h.externalComparisonAdopt,"external comparison dispatch preserves compare-only choice");break;
    case 8:check(h.externalComparisons==1&&h.externalComparisonAdopt,"external comparison dispatch preserves compare-and-connect choice");break;
    case 9:check(h.candidateTimes==1&&h.nodeStore.selections==0&&h.saved.writes==0,"retained-prefix TCP timing dispatch cannot mutate the route");break;
    default:check(h.infoTitle.equals("Path throughput / Auto MTU")&&h.info.contains("No proven"),"unmeasured MTU is truthful");
   }
   check(action>=7||h.externalComparisons==0,"existing Performance actions cannot start an external comparison");
   check(action<7||h.telemetry.allSamples==0&&h.telemetry.nodeSamples==0&&h.telemetry.currentSamples==0&&h.telemetry.speedBytes==0&&h.routed==0,"external comparison dispatch cannot substitute Router or current-path measurement");
  }
  for(int action:new int[]{0,3}){ProductDialogHarness h=new ProductDialogHarness();h.connection.connected=false;h.showPerformance();shown(10,"Performance").clickItem(action);check(h.telemetry.currentSamples==0&&h.telemetry.speedBytes==0,"disconnected path speed cannot run");}
 }
 static void nodes(){
  ProductDialogHarness h=new ProductDialogHarness();h.showNodes();AlertDialog d=shown(2,"Choose node");check(d.items[1].contains("list only"),"no invented external coordinates");d.clickItem(1);check(h.selected.equals("external"),"exact external node callback");
  h=new ProductDialogHarness();h.catalog.items.clear();h.showNodes();check(AlertDialog.last.items==null&&AlertDialog.last.message!=null,"empty node informational dialog retained");
 }
 static void polling(){
  externalPolling();
  ProductDialogHarness h=new ProductDialogHarness();h.refreshTelemetry(true);check(h.currentPathMs==3&&h.currentPathReceipt==h.telemetry.path&&h.liveLatency.getText().toString().contains("3.0"),"resumed polling did not publish current captured result");h.telemetry.path.stale=true;AndroidMTUMeasurementGate.busy=true;h.refreshTelemetry(true);check(h.currentPathMs==0&&h.currentPathReceipt==null&&h.liveLatency.getText().toString().equals("-- ms")&&h.telemetry.currentCalls==1,"owned measurement kept stale current RTT label");AndroidMTUMeasurementGate.busy=false;
  h=new ProductDialogHarness();h.refreshTelemetry(true);h.connection.connected=false;h.telemetryBusy=true;h.refreshTelemetry(true);check(h.currentPathMs==0&&h.currentPathReceipt==null,"busy polling retained disconnected path label");
  h=new ProductDialogHarness();h.telemetry.delayPath=true;h.refreshTelemetry(true);h.telemetryGeneration++;h.resumed=false;h.telemetry.pending.result(h.telemetry.path,null);check(h.currentPathMs==0&&h.currentPathReceipt==null&&!h.telemetryBusy,"paused or newer UI adopted delayed current RTT");
  h=new ProductDialogHarness();h.telemetry.delayPath=true;h.refreshTelemetry(true);h.telemetry.path.stale=true;h.telemetry.pending.result(h.telemetry.path,null);check(h.currentPathMs==0&&h.currentPathReceipt==null,"delayed stale native path published current RTT");
 }

 static void externalPolling(){
  AndroidHomeStateStore.state.logicalMode="external";
  ProductDialogHarness h=new ProductDialogHarness();h.refreshTelemetry(true);check(h.currentExternalReceipt==h.externalTelemetry.result&&h.currentPathReceipt==null&&h.currentPathMs==6&&h.liveLatency.getText().toString().contains("6.0 ms HTTPS")&&h.telemetry.currentCalls==0,"external live polling fell back to ordinary RTT or lost its HTTPS label");
  check(h.liveExternalMedian("external")==6&&h.liveExternalMedian("another")==0,"map attributed active path to another external node");h.showLiveTelemetry();check(h.infoTitle.equals("Live HTTPS path response")&&h.info.contains("3 HTTPS responses")&&h.telemetry.currentCalls==0,"live details launched ambient/private RTT");
  h.externalTelemetry.result.stale=true;AndroidMTUMeasurementGate.busy=true;h.refreshTelemetry(true);check(h.currentExternalReceipt==null&&h.currentPathMs==0&&h.liveExternalMedian("external")==0&&h.externalTelemetry.calls==1,"busy polling retained an expired external map/Disconnect value");AndroidMTUMeasurementGate.busy=false;
  for(String fault:new String[]{"queued-owner","pause","generation","disconnect"}){
   h=new ProductDialogHarness();h.externalTelemetry.delay=true;h.refreshTelemetry(true);check(h.telemetryBusy&&h.externalTelemetry.calls==1,"external polling did not retain asynchronous owner");
   if(fault.equals("queued-owner"))h.externalTelemetry.result.stale=true;if(fault.equals("pause"))h.resumed=false;if(fault.equals("generation"))h.telemetryGeneration++;if(fault.equals("disconnect")){h.connection.connected=false;h.refreshTelemetry(true);check(h.externalTelemetry.cancels>0,"disconnect did not cancel captured external response");}
   h.externalTelemetry.running=false;h.externalTelemetry.pending.finished(h.externalTelemetry.result,null);check(h.currentExternalReceipt==null&&h.currentPathMs==0&&!h.telemetryBusy,"late external response escaped its queued UI owner: "+fault);
  }
  AndroidHomeStateStore.state.logicalMode="raw-tunnel";
 }
 static void profiles(){ProductDialogHarness h=new ProductDialogHarness();h.showProfileManager();shown(3,"Router profiles").clickItem(2);check(h.profile.equals("c"),"exact stored router profile callback");}
 static void execution(){
  String[] policies={"local","server","auto"};
  for(int i=0;i<3;i++){
   ProductDialogHarness h=new ProductDialogHarness();h.chooseMultihopExecution(h.nodeById("a"),h.nodeById("b"),"hysteria2","max-quic-awg",h.capture());shown(3,"Multihop execution").clickItem(i);
   check(h.saved.writes==1&&h.saved.getString("multihop_execution","").equals(policies[i]),"exact saved execution preference");
   check(h.saved.getString(MULTI_ENTRY,"").equals("a")&&h.saved.getString(MULTI_EXIT,"").equals("b")&&h.saved.getString(MULTI_MODE,"").equals("hysteria2")&&h.saved.getString("multihop_entry_mode","").equals("max-quic-awg"),"frozen entry/exit/mode choices preserved");
   check(h.multihopToggle.isChecked()&&Boolean.TRUE.equals(h.saved.values.get(MULTI_ON)),"multihop enabled only by actual choice");
  }
  ProductDialogHarness h=new ProductDialogHarness();h.chooseMultihopExecution(h.nodeById("a"),h.nodeById("b"),"wg","wg",h.capture());h.busy=true;shown(3,"Multihop execution").clickItem(2);check(h.saved.writes==0&&!h.multihopToggle.isChecked(),"late busy refuses saved multihop mutation");
  h=new ProductDialogHarness();var captured=h.capture();h.chooseMultihopExecution(h.nodeById("a"),h.nodeById("b"),"wg","wg",captured);captured.stale=true;shown(3,"Multihop execution").clickItem(2);check(h.saved.writes==0&&h.message.contains("Retest"),"late changed capture cannot save an old measured choice");
 }
 static void entry(){
  ProductDialogHarness h=new ProductDialogHarness();h.configurePairMultihop();AlertDialog d=shown(3,"Multihop entry");
  String note=((TextView)((LinearLayout)d.customTitle).children.get(1)).getText().toString();
  check(note.contains("Router VPN will then briefly establish and prove this entry")&&note.contains("disconnect")&&note.contains("press Connect"),"Router entry discloses temporary proved measurement before selection");
  d.clickItem(2);check(h.entry.equals("c")&&h.exit.equals("3"),"chosen entry and complete candidate list passed to measurement");
  h=new ProductDialogHarness();h.busy=true;h.configurePairMultihop();check(h.entry.isEmpty(),"busy multihop setup cannot create temporary tunnel");
  for(String protocol:new String[]{"shadowsocks","hysteria2","wireguard","amneziawg"})for(int routers:new int[]{1,3}){
   h=new ProductDialogHarness();while(h.nodeStore.nodes.size()>routers)h.nodeStore.nodes.remove(h.nodeStore.nodes.size()-1);
   AndroidStandardExitStore.Entry first=new AndroidStandardExitStore.Entry("provider",protocol);h.exitStore.entries.add(first);
   h.configurePairMultihop();d=shown(routers+1,"Multihop entry");check(d.items[routers].contains("Imported provider")&&d.items[routers].contains(protocol),"imported entry keeps its own visible identity");
   d.clickItem(routers);check(h.importedEntry==first&&h.importedFinals==h.nodeStore.nodes&&h.entry.isEmpty()&&h.saved.writes==0,"imported selection preserves its source without starting a Router measurement or saving early");
  }
  h=new ProductDialogHarness();h.nodeStore.nodes.clear();h.exitStore.entries.add(new AndroidStandardExitStore.Entry("provider"));AlertDialog.last=null;h.configurePairMultihop();
  check(AlertDialog.last==null&&h.importedEntry==null,"imported entry cannot fabricate a missing paired final");
 }
 static void ordered(){
  ProductDialogHarness h=new ProductDialogHarness();h.configureMultihop();shown(2,"Choose multihop path").clickItem(0);
  check(h.ordered!=null&&h.ordered.catalog.owner==h.nodeStore&&h.ordered.catalog.selectedId.equals("a")&&h.ordered.members().size()==1&&h.ordered.members().get(0).source.id.equals("a"),"ordered choice lost original constructor/catalog/final capture");
  check(h.saved.writes==0&&h.nodeStore.selections==0&&h.entry.isEmpty(),"opening ordered draft mutated selection or entered pair measurement");
  h=new ProductDialogHarness();h.configureMultihop();shown(2,"Choose multihop path").clickItem(1);shown(3,"Multihop entry").clickItem(1);
  check(h.ordered==null&&h.entry.equals("b")&&h.nodeStore.catalogCaptures==0,"pair choice entered ordered constructor");
  h=new ProductDialogHarness();h.saved.values.put(SELECTED_KIND,"external");h.configureMultihop();shown(3,"Multihop entry").clickItem(0);
  check(h.ordered==null&&h.entry.equals("a")&&h.nodeStore.catalogCaptures==0,"external entry was replaced by an ordered Router draft");
  h=new ProductDialogHarness();h.busy=true;AlertDialog.last=null;h.configureMultihop();
  check(AlertDialog.last==null&&h.nodeStore.catalogCaptures==0,"busy chooser created an ordered capture");
  h=new ProductDialogHarness();h.configureMultihop();AlertDialog prompt=shown(2,"Choose multihop path");h.busy=true;prompt.clickItem(0);
  check(h.ordered==null&&h.nodeStore.catalogCaptures==0,"late busy constructor captured private sources");
  for(String fault:new String[]{"missing-wg","short-key"}){h=new ProductDialogHarness();h.nodeStore.identityFault=fault;h.configureMultihop();shown(2,"Choose multihop path").clickItem(0);check(h.ordered!=null&&h.ordered.members().isEmpty(),"ordered constructor selected a final without its original paired identity: "+fault);}
  h=new ProductDialogHarness();h.nodeStore.identityFault="wrong-proof";h.configureMultihop();shown(2,"Choose multihop path").clickItem(0);check(h.ordered==null&&h.message.contains("proof does not match"),"ordered constructor accepted a substituted paired proof");
  h=new ProductDialogHarness();h.nodeStore.staleCatalog=true;h.configureMultihop();shown(2,"Choose multihop path").clickItem(0);
  check(h.ordered==null&&h.message.contains("catalog changed"),"ordered constructor adopted changed original catalog");
  // An empty draft skips final-mode discovery and still needs the terminal
  // constructor guard; retain its independent causal control.
  h=new ProductDialogHarness();h.nodeStore.selected="";h.configureMultihop();shown(2,"Choose multihop path").clickItem(0);
  check(h.ordered!=null&&h.ordered.members().isEmpty()&&h.saved.writes==0,"valid empty ordered draft cannot open without publishing selection");
  h=new ProductDialogHarness();h.nodeStore.selected="";h.nodeStore.staleCatalog=true;h.configureMultihop();shown(2,"Choose multihop path").clickItem(0);
  check(h.ordered==null&&h.message.contains("catalog changed"),"ordered constructor adopted changed original catalog for empty draft");
  h=new ProductDialogHarness();ProductDialogHarness original=h;h.nodeStore.duringCapture=()->original.saved.values.put(SELECTED_ID,"b");h.configureMultihop();shown(2,"Choose multihop path").clickItem(0);
  check(h.ordered==null&&h.message.contains("connection changed"),"ordered constructor adopted changed preferences");
 }
 static void exits(){
  ProductDialogHarness h=new ProductDialogHarness();List<AndroidNodeStore.Node> exits=Arrays.asList(h.nodeById("b"),h.nodeById("c"));
  var captured=new AndroidViaEntryLatencyProbe.Result(h.nodeById("a"),exits,Collections.singletonList(new AndroidTelemetry.Result("b",4.2)));
  h.showViaEntryExitPicker(captured,null);
  AlertDialog d=shown(3,"Multihop hop 2");check(d.items[0].contains("Fastest")&&d.items[1].contains("4.2 ms")&&d.items[2].contains("unavailable"),"only measured via-entry result gets a response time");d.clickItem(2);check(h.entry.equals("a")&&h.exit.equals("c"),"exact manual second-hop callback");
  captured=new AndroidViaEntryLatencyProbe.Result(h.nodeById("a"),exits,Arrays.asList(new AndroidTelemetry.Result("b",40),new AndroidTelemetry.Result("c",7)));
  h.showViaEntryExitPicker(captured,null);d=shown(3,"Multihop hop 2");check(d.items[0].contains("Node c")&&d.items[1].contains("Node c"),"measured Fastest and sorting use the lowest candidate response");d.clickItem(0);check(h.exit.equals("c"),"Fastest routes to the measured exit");
  h=new ProductDialogHarness();captured=new AndroidViaEntryLatencyProbe.Result(h.nodeById("a"),exits,Arrays.asList(new AndroidTelemetry.Result("b",1,40,50,0),new AndroidTelemetry.Result("c",20,20,50,0)));
  h.showViaEntryExitPicker(captured,null);d=shown(3,"Multihop hop 2");check(d.items[0].contains("Node c")&&d.items[1].contains("Node c"),"via-entry UI ranks trimmed mean despite favorable median");d.clickItem(0);check(h.exit.equals("c"),"via-entry Fastest selected robust winner");
  h=new ProductDialogHarness();captured=new AndroidViaEntryLatencyProbe.Result(h.nodeById("a"),exits,Arrays.asList(new AndroidTelemetry.Result("b",1,1,49,1),new AndroidTelemetry.Result("c",7)));
  h.showViaEntryExitPicker(captured,null);d=shown(3,"Multihop hop 2");check(d.items[0].contains("Node c")&&d.items[2].contains("no comparison score"),"partial via-entry row obtained a score or lost its diagnostic label");
  h=new ProductDialogHarness();captured=new AndroidViaEntryLatencyProbe.Result(h.nodeById("a"),exits,Collections.emptyList());
  h.showViaEntryExitPicker(captured,new IllegalStateException("no route proof"));d=shown(3,"Multihop hop 2");check(d.items[0].contains("unavailable")&&((TextView)((LinearLayout)d.customTitle).children.get(1)).getText().toString().contains("no route proof"),"failed proof remains visible without invented latency");d.clickItem(0);check(h.exit.equals("2"),"unavailable Fastest retries measurements instead of guessing a winner");
  h=new ProductDialogHarness();captured=new AndroidViaEntryLatencyProbe.Result(h.nodeById("a"),exits,Collections.singletonList(new AndroidTelemetry.Result("b",4.2)));h.showViaEntryExitPicker(captured,null);d=shown(3,"Multihop hop 2");captured.stale=true;d.clickItem(0);check(h.exit.isEmpty()&&h.message.contains("Retest"),"a delayed Fastest callback cannot reuse an old capture");
 }
 public static void main(String[] args){
  if(args.length>0){switch(args[0]){case "0":fastest();break;case "1":performance();break;case "2":nodes();break;case "3":profiles();break;case "4":execution();break;case "5":entry();break;case "6":exits();break;case "7":ordered();break;default:throw new AssertionError("unknown negative");}return;}
  AlertDialog broken=new AlertDialog.Builder(new ProductDialogHarness()).setMessage("suppresses list").setItems(new String[]{"unreachable"},(d,i)->{throw new AssertionError("hidden callback ran");}).show();
  check(!broken.itemsVisible(),"AOSP precedence double must reject original form");
  try{broken.clickItem(0);throw new AssertionError("hidden item clickable");}catch(IllegalStateException expected){checks++;}
  fastest();performance();nodes();profiles();execution();entry();exits();polling();ordered();
  System.out.println("Android shipping ProductActivity dialog actions: PASS "+checks+" checks (AOSP dialog boundary; OS/network handles doubled)");
 }
}
'''


def main():
    handlers = [method(signature) for signature in SIGNATURES]
    for signature, handler in zip(SIGNATURES, handlers):
        assert handler.count("choiceDialog(") == 1, signature
    support = method("void showRouterFastConnectMenu(") + method("AlertDialog.Builder choiceDialog(") + method("TextView text(") + method("int dp(") + method("void refreshTelemetry(") + method("void clearCurrentTelemetry(") + method("void refreshExternalTelemetry(") + method("double liveExternalMedian(") + method("void showLiveTelemetry(")
    with tempfile.TemporaryDirectory(prefix="routervpn-product-dialog-") as work:
        tmp = Path(work)
        sources = dict(W.UI)
        sources["android/app/AlertDialog.java"] = sources["android/app/AlertDialog.java"].replace(
            "public Builder setNegativeButton(",
            "public Builder setNeutralButton(CharSequence text,OnClickListener listener){return button(-3,text,listener);}\n  public Builder setNegativeButton(")
        sources["android/app/AlertDialog.java"] = sources["android/app/AlertDialog.java"].replace(
            "public CharSequence title,message;", "public boolean cancelable=true;public void setMessage(CharSequence value){message=value;}public CharSequence title,message;").replace(
            "public Builder setTitle(", "public Builder setCancelable(boolean value){dialog.cancelable=value;return this;}public Builder setTitle(")
        # The real Android API accepts CharSequence[], including the imported
        # entry labels. Preserve the same message/list precedence and callbacks.
        original_items="public Builder setItems(String[] values,OnClickListener listener){dialog.items=values.clone();dialog.itemClick=listener;return this;}"
        assert sources["android/app/AlertDialog.java"].count(original_items)==1
        sources["android/app/AlertDialog.java"]=sources["android/app/AlertDialog.java"].replace(original_items,
            "public Builder setItems(CharSequence[] values,OnClickListener listener){dialog.items=new String[values.length];for(int i=0;i<values.length;i++)dialog.items[i]=values[i].toString();dialog.itemClick=listener;return this;}")
        sources["android/graphics/Color.java"] = "package android.graphics;public final class Color {public static final int WHITE=-1;}"
        sources["android/os/SystemClock.java"] = "package android.os;public final class SystemClock {public static long elapsedRealtime(){return 10000;}}"
        sources["android/content/SharedPreferences.java"] = """package android.content;
public interface SharedPreferences {String getString(String key,String fallback);default java.util.Map<String,?> getAll(){return java.util.Collections.emptyMap();}default Editor edit(){throw new UnsupportedOperationException();}
interface Editor{Editor putString(String key,String value);Editor putBoolean(String key,boolean value);void apply();}}"""
        via_source=(JAVA / "AndroidViaEntryLatencyProbe.java").read_text()
        ranking=[]
        for marker in ("        static double score(","        AndroidNodeStore.Node fastest("):
            start=via_source.index(marker);end=via_source.index("{",start)+1;depth=1
            while depth:
                depth+=(via_source[end]=="{")-(via_source[end]=="}");end+=1
            ranking.append(via_source[start:end])
        node_source=(JAVA/'AndroidNodeStore.java').read_text()
        domain=next(line for line in node_source.splitlines() if 'private static final String NODE_PROOF_DOMAIN' in line)
        identity_helpers=domain+"\n"+"\n".join(block(node_source,marker) for marker in (
            '    static String stableNodeIdentity(', '    private static String wireGuardPeerPublicKey(',
            '    private static JSONObject selectedProfile(', '    private static String hex('))
        sources["com/eabusham/routervpn/ProductBoundaries.java"] = (BOUNDARIES.replace("  // SHIPPING_VIA_RANKING", "\n".join(ranking))
            .replace('// SHIPPING_PAIRED_IDENTITY',block(node_source,'        void requirePairedIdentity('))
            .replace('// SHIPPING_NODE_IDENTITY_HELPERS',identity_helpers))
        sources['android/util/Base64.java']='package android.util;public final class Base64{public static final int DEFAULT=0;public static byte[] decode(String value,int flags){return java.util.Base64.getMimeDecoder().decode(value);}}'
        sources['com/eabusham/routervpn/AndroidProfileSelection.java']=(JAVA/'AndroidProfileSelection.java').read_text()
        profile_source=(JAVA/"AndroidConnectionProfileStore.java").read_text()
        constants=profile_source[profile_source.index('    private static final String FILE_NAME'):profile_source.index('    private static final SecureRandom RANDOM')]
        selection_keys=profile_source[profile_source.index('    private static final String[] SELECTION_KEYS'):profile_source.index('    static final class Record')]
        fields=profile_source[profile_source.index('    private final Context context;'):profile_source.index('    AndroidConnectionProfileStore(')]
        profile_methods="\n".join(block(profile_source,marker) for marker in (
            '    AndroidConnectionProfileStore(', '    static void applySelection(',
            '    synchronized Map<String,Object> orderedEditorPreferences(', '    private Map<String,Object> snapshotPreferences(',
            '    private void requireIdle(', '    private SharedPreferences prefs('))
        # Persisted-row loading is outside this choice-handler fixture; refusing
        # that uncomposed branch cannot authorize a fabricated saved capture.
        sources["com/eabusham/routervpn/AndroidConnectionProfileStore.java"]=(
            "package com.eabusham.routervpn;import android.content.*;import java.io.File;import java.util.*;final class AndroidConnectionProfileStore{"
            +constants+selection_keys+fields+profile_methods
            +'AndroidNodeStore.ChainCapture orderedEditorPath(){throw new IllegalStateException("Saved ordered replay requires the complete profile fixture");}}')
        ordered_source=(JAVA/'AndroidOrderedPathSelection.java').read_text()
        ordered_fields=ordered_source[ordered_source.index('    static final class Member'):ordered_source.index('    AndroidOrderedPathSelection(')]
        ordered_methods="\n".join(block(ordered_source,marker) for marker in (
            '    AndroidOrderedPathSelection(', '    List<Member> members(', '    List<String> finalModes(',
            '    void requireCurrent(', '    private static boolean hasMode('))
        ordered_java=('package com.eabusham.routervpn;import org.json.*;import java.util.*;final class AndroidOrderedPathSelection{'
            +ordered_fields+ordered_methods+'}')
        sources['com/eabusham/routervpn/AndroidOrderedPathSelection.java']=ordered_java

        for name, text in sources.items():
            path = tmp / name;path.parent.mkdir(parents=True, exist_ok=True);path.write_text(text)
        target = tmp / "com/eabusham/routervpn/ProductDialogHarness.java"
        def compile_run(parts, negative=None, expected_failure="items must be reachable"):
            target.write_text(HARNESS_PREFIX + "\n".join(parts) + support + HARNESS_SUFFIX)
            build = subprocess.run(["javac", "--release", "17", "-cp", JSON_JAR, "-d", str(tmp), *map(str, tmp.rglob("*.java"))], text=True, capture_output=True, timeout=30)
            assert build.returncode == 0, build.stderr
            run = subprocess.run(["java", "-cp", os.pathsep.join((str(tmp), JSON_JAR)), "com.eabusham.routervpn.ProductDialogHarness", *([] if negative is None else [str(negative)])], text=True, capture_output=True, timeout=15)
            if negative is None:
                assert run.returncode == 0, run.stdout+run.stderr
                print(run.stdout.strip())
            else:
                assert run.returncode != 0 and expected_failure in run.stderr, f"negative {negative} survived or failed for unrelated reason: {run.stdout}{run.stderr}"
        compile_run(handlers)
        # An exact old builder on any affected surface must fail its actual action test.
        for index in range(len(handlers)):
            changed = handlers.copy()
            changed[index] = changed[index].replace("choiceDialog(", "brokenChoiceDialog(", 1)
            changed.append("private AlertDialog.Builder brokenChoiceDialog(String title,String note){return new AlertDialog.Builder(this).setTitle(title).setMessage(note);}")
            compile_run(changed, index)
        ordered_target=tmp/'com/eabusham/routervpn/AndroidOrderedPathSelection.java'
        original_constructor=block(ordered_java,'    AndroidOrderedPathSelection(')
        assert original_constructor.count('        requireCurrent();')==1
        ordered_target.write_text(ordered_java.replace(original_constructor,original_constructor.replace('        requireCurrent();','        // defect: omit original complete capture validation'),1))
        try:
            compile_run(handlers,7,'ordered constructor adopted changed original catalog for empty draft')
        finally:
            ordered_target.write_text(ordered_java)
        assert ordered_java.count('source.requirePairedIdentity();')==1
        ordered_target.write_text(ordered_java.replace('source.requirePairedIdentity();','/* defect: omit original paired identity */',1))
        try:
            compile_run(handlers,7,'ordered constructor selected a final without its original paired identity')
        finally:
            ordered_target.write_text(ordered_java)
        for old,new,expected in (
            ("else chooseImportedRouterFinal(imports.get(w-nodes.size()),nodes);",
             "else prepareViaEntryExitMeasurement(nodes.get(0),nodes);",
             "imported selection preserves its source without starting a Router measurement or saving early"),
            ("Router VPN will then briefly establish and prove this entry", "Router entries offer measurements",
             "Router entry discloses temporary proved measurement before selection"),
        ):
            changed=handlers.copy();assert changed[5].count(old)==1
            changed[5]=changed[5].replace(old,new)
            compile_run(changed,5,expected)
    print("Android product dialogs: all seven original-builder and the ordered-choice builder controls rejected")
    print("Android product dialogs: imported dispatch, temporary-probe disclosure and ordered-constructor capture/paired-identity defects rejected")


if __name__ == "__main__":
    main()
