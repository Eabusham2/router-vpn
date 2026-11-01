#!/usr/bin/env python3
"""Execute the selected external benchmark, drain and private historical store.

Shipping Java measurement/controller/store classes run unchanged. The original
runtime receipt and validation methods are extracted verbatim; their actual
Connect adoption is exercised separately by test_android_runtime_teardown.py.
Native encrypted transport has an explicit handle boundary here, with the
shipping service owner covered by test_android_external_hop_measurement.py and
the fifty actual HTTPS exchanges covered by the shared Go TLS fixture.
"""
from pathlib import Path
import importlib.util
import os
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
JAVA = ROOT / 'android/app/src/main/java/com/eabusham/routervpn'
spec = importlib.util.spec_from_file_location('external_statistics_stores', ROOT / 'android/test_android_node_usage.py')
U = importlib.util.module_from_spec(spec)
spec.loader.exec_module(U)

RUNTIME = r'''
 private android.content.Context context;
 private final java.util.concurrent.atomic.AtomicBoolean closed=new java.util.concurrent.atomic.AtomicBoolean();
 private boolean disconnectRequested,revalidationTeardown,teardownInProgress;
 private String torNativeSession="native-1",externalNativeSession="native-1",requestedExecution="local";
 private MeasurementSource activeMeasurementSource;
 // SHIPPING_MEASUREMENT_SOURCE
 // SHIPPING_CAPTURE
 // SHIPPING_REQUIRE
 void fixtureAdopt(android.content.Context c,AndroidNodeStore.Node router,AndroidStandardExitStore.Entry ordinary,AndroidStandardExitStore.Entry exit,String requested,String chosen)throws Exception{
  context=c;execution=requested;requestedExecution=requested;selected=chosen;
  String entry=router!=null?router.id:ordinary!=null?ordinary.id:"",mode=router!=null?"wg":ordinary!=null?"shadowsocks":"";
  String source=router!=null?AndroidExternalPolicy.entryDigest(router.file):ordinary!=null?AndroidStandardExitStore.snapshot(ordinary):"";
  boolean tor=AndroidTorProfile.isTor(exit.protocol);
  if(tor)AndroidHomeStateStore.beginTorExternal(c,exit.id,exit.name,exit.protocol,entry,mode);else AndroidHomeStateStore.beginPolicyExternal(c,exit.id,exit.name,exit.protocol,exit.expectedPublicIp,entry,mode);
  AndroidHomeStateStore.Snapshot started=AndroidHomeStateStore.snapshot(c);
  if(!(tor?AndroidHomeStateStore.connectedTorExternal(c,started,"8.8.4.4"):AndroidHomeStateStore.connectedPolicyExternal(c,started,"8.8.4.4")))throw new AssertionError("controlled native boundary failed Home adoption");
  activeMeasurementSource=new MeasurementSource(AndroidHomeStateStore.snapshot(c),"native-1",AndroidStandardExitStore.snapshot(exit),router!=null?"router-vpn":ordinary!=null?"external":"direct",source,router==null?null:router.file.getCanonicalFile(),requested,chosen);
 }
 void replaceFixtureReceipt(){MeasurementSource old=activeMeasurementSource;activeMeasurementSource=new MeasurementSource(old.home,old.nativeSession,old.exitSource,old.entryKind,old.entrySource,old.routerEntry,old.requestedExecution,old.selectedExecution);}
'''

NATIVE = r'''package com.eabusham.routervpn;
import java.util.concurrent.*;import java.util.function.*;import org.json.*;
final class LayeredVpnService {
 static volatile HopMeasurementOwner current;static volatile CountDownLatch drainEntered,drainRelease;
 static volatile boolean valid=true,quiesceFailed;static volatile String fault="";static int captures,traffic;
 static void reset(){current=null;drainEntered=null;drainRelease=null;valid=true;quiesceFailed=false;fault="";captures=traffic=0;}
 static void quiesceMTUForSpeedLab(Consumer<Throwable> cb){cb.accept(quiesceFailed?new IllegalStateException("MTU native workers pending"):null);}
 static HopMeasurementOwner captureHopMeasurement(String id){throw new AssertionError("external selected node used generic/private path measurement");}
 static HopMeasurementOwner captureExternalHopMeasurement(String id,String exit,String nativeID,String home,long generation){
  if(!nativeID.equals("native-1")||home.isEmpty()||generation<0||exit.isEmpty()||!valid)throw new IllegalStateException("unowned external handle");captures++;return current=new HopMeasurementOwner(id,exit);
 }
 static final class HopMeasurementOwner {
  final String id,exit;volatile boolean began,drained;int cancels,drains;
  HopMeasurementOwner(String id,String exit){this.id=id;this.exit=exit;}
  void require(){if(!valid||current!=this)throw new IllegalStateException("captured native owner retired");}
  void start(){require();began=true;traffic++;}boolean started(){return began;}
  String requestID(){return id;}String configIdentity(){return "b".repeat(64);}String networkIdentity(){return "c".repeat(64);}
  String status()throws Exception{
   require();JSONObject stats=new JSONObject().put("samples",50).put("min_ms",1).put("median_ms",2).put("average_ms",2.1).put("p90_ms",3).put("max_ms",4).put("jitter_ms",0.3);
   JSONObject benchmark=new JSONObject().put("schema",1).put("measurement","routed-https-response-after-tls").put("endpoint","https://speed.cloudflare.com/__down?bytes=1").put("attempts",50).put("failed",0).put("distribution",stats).put("trimmed_mean_ms",2);
   JSONObject row=new JSONObject().put("node_id",exit).put("role","exit").put("kind","public-path").put("label","External path → Cloudflare edge").put("ready",true).put("benchmark",benchmark);
   JSONObject status=new JSONObject().put("request_id",id).put("stage","complete").put("complete",true).put("drained",drained).put("results",new JSONArray().put(row));
   switch(fault){case "wrong-node":row.put("node_id","other");break;case "private":row.put("kind","private-node");break;case "entry":row.put("role","entry");break;case "not-ready":row.put("ready",false);break;case "typed-ready":row.put("ready","true");break;case "transfer":row.put("download",new JSONObject());break;
    case "49":stats.put("samples",49);break;case "attempts":benchmark.put("attempts",49);break;case "failed":benchmark.put("failed",1);break;case "typed-count":benchmark.put("attempts","50");break;case "endpoint":benchmark.put("endpoint","https://other.invalid/");break;case "icmp":benchmark.put("measurement","icmp-rtt");break;case "negative":stats.put("min_ms",-1);break;case "order":stats.put("median_ms",8);break;case "trimmed":benchmark.put("trimmed_mean_ms",9);break;case "status-failure":status.put("failure","native source lost");break;
    case "stage-cancelled":status.put("stage","cancelled");break;case "stage-invalidated":status.put("stage","invalidated");break;
   }return status.toString();
  }
  void cancel(){cancels++;}
  void drain()throws Exception{drains++;if(drainEntered!=null)drainEntered.countDown();if(drainRelease!=null&&!drainRelease.await(6,TimeUnit.SECONDS))throw new IllegalStateException("fixture drain held too long");drained=true;}
  interface Commit{void run()throws Exception;}
  void commit(Commit write)throws Exception{require();if(!drained||!AndroidMTUMeasurementGate.held())throw new AssertionError("save escaped native drain or MTU owner");write.run();}
 }
}
'''

ACTIVITY = r'''package com.eabusham.routervpn;
import android.content.*;
final class StatisticsActivity extends android.app.Activity {
 static final String SELECTED_ID="selected_id";AndroidNodeStore nodeStore;AndroidStandardExitStore exitStore;
 final RouterStatisticsBoundary telemetry=new RouterStatisticsBoundary();String title="",message="";
 SharedPreferences prefs(){return getSharedPreferences("statistics-selection",0);}boolean isExternalSelected(){return true;}
 AndroidNodeStore.Node nodeById(String id){throw new AssertionError("external saved statistics read the active Router");}
 void dialog(String title,String message){this.title=title;this.message=message;}void toast(String text){message=text;}String safe(Throwable error){return error.getMessage();}
 void saved(){showSavedStatistics();}
 // SHIPPING_SAVED
}
final class RouterStatisticsBoundary {AndroidNodeStatistics.Record savedStatistics(AndroidNodeStore.Node n){throw new AssertionError("external saved statistics borrowed Router data");}}
'''

HARNESS = r'''package com.eabusham.routervpn;
import android.content.*;import java.io.*;import java.nio.file.*;import java.util.*;import java.util.concurrent.*;import org.json.*;
public final class ExternalStatisticsTest {
 static int checks;static void check(boolean ok,String message){checks++;if(!ok)throw new AssertionError(message);}
 static void await(CountDownLatch latch,String message)throws Exception{check(latch.await(4,TimeUnit.SECONDS),message);}
 static final class Callback implements AndroidExternalNodeBenchmark.Callback{
  final CountDownLatch done=new CountDownLatch(1);volatile AndroidExternalNodeStatistics.Record result;volatile Throwable error;
  public void progress(String text){}public void finished(AndroidExternalNodeStatistics.Record value,Throwable failure){result=value;error=failure;done.countDown();}
  void joined()throws Exception{await(done,"external request failed to finish after native drain");check(!AndroidMTUMeasurementGate.held(),"external request leaked its MTU hold");}
 }
 static final class Fixture implements AutoCloseable{
  final StatisticsActivity activity;final AndroidNodeStore store;final AndroidStandardExitStore exits;final AndroidNodeStore.Node router;
  final AndroidStandardExitStore.Entry exit,entry;final AndroidStandardExitRuntime runtime;final AndroidExternalNodeBenchmark benchmark;
  Fixture(Path root,String shape)throws Exception{
   check(!AndroidMTUMeasurementGate.held(),"previous fixture still owns MTU");Context.preferences.clear();Context.nextFiles=Files.createTempDirectory(root,"external50-").toFile();activity=new StatisticsActivity();AndroidRuntimeRegistry.instance=new AndroidRuntimeRegistry();runtime=AndroidRuntimeRegistry.instance.standardExit;
   NativeUsageBoundary.reset(activity);AndroidVpnMutationGuard.busy=false;store=new AndroidNodeStore(activity);exits=new AndroidStandardExitStore(activity);activity.nodeStore=store;activity.exitStore=exits;
   router=store.importBundle(new JSONObject().put("profileSchemaVersion",4).put("nodeProofId","a".repeat(64)).put("profiles",new JSONObject().put("wg",new JSONObject().put("fixture","engine-boundary"))).put("modes",new JSONArray().put(new JSONObject().put("id","wg"))).put("activeRouterProfileId","home").put("routerProfiles",new JSONArray().put(new JSONObject().put("id","home").put("name","Router").put("node_proof_id","a".repeat(64)).put("endpoint","192.0.2.10").put("router_api","https://192.0.2.10:8443").put("api_token","private-router-token"))).toString().getBytes(java.nio.charset.StandardCharsets.UTF_8));
   exit=external("external-selected",shape.equals("ordinary")?"tor":"shadowsocks");entry=external("ordinary-entry","shadowsocks");exits.save(entry);exits.save(exit);activity.prefs().edit().putString("selected_id",exit.id).apply();
   runtime.fixtureAdopt(activity,shape.equals("router")?router:null,shape.equals("ordinary")?entry:null,exit,shape.equals("router")?"auto":"local",shape.equals("router")?"server":"local");
   LayeredVpnService.reset();benchmark=new AndroidExternalNodeBenchmark(activity,runtime);android.system.Os.failTarget="";
  }
  AndroidStandardExitStore.Entry external(String id,String protocol){AndroidStandardExitStore.Entry e=new AndroidStandardExitStore.Entry();e.id=id;e.name=id;e.protocol=protocol;e.server="8.8.8.8";e.serverPort=443;e.method="aes-256-gcm";e.secret="private-external-secret";e.expectedPublicIp="8.8.4.4";return e;}
  File file(){return new File(activity.getFilesDir(),AndroidExternalNodeStatistics.FILE_NAME);}File exitFile(){return new File(activity.getFilesDir(),"standard-exits.json");}
  Callback run(){Callback cb=new Callback();benchmark.run(exit.id,cb);return cb;}
  byte[] saved()throws Exception{return Files.readAllBytes(file().toPath());}
  void baseline()throws Exception{Callback cb=run();cb.joined();check(cb.error==null&&cb.result!=null,"valid external result was not saved: "+cb.error);}
  void hold(){LayeredVpnService.drainEntered=new CountDownLatch(1);LayeredVpnService.drainRelease=new CountDownLatch(1);}
  void release(){if(LayeredVpnService.drainRelease!=null)LayeredVpnService.drainRelease.countDown();}
  public void close(){release();benchmark.cancel();AndroidHomeStateStore.disconnected(activity);android.system.Os.failTarget="";}
 }
 static void ordinary(Path root)throws Exception{
  for(String shape:List.of("direct","router","ordinary"))try(Fixture f=new Fixture(root,shape)){
   byte[] original=Files.readAllBytes(f.exitFile().toPath()),router=Files.readAllBytes(f.router.file.toPath());f.hold();Callback cb=f.run();check(cb.error==null,"benchmark preflight failed: "+cb.error);await(LayeredVpnService.drainEntered,"native latency request never entered drain");
   check(!f.file().exists()&&cb.done.getCount()==1&&AndroidMTUMeasurementGate.held()&&f.benchmark.isRunning(),"complete status saved or released MTU before native drain");
   f.release();cb.joined();check(cb.error==null&&cb.result!=null,"captured complete benchmark rejected: "+cb.error);check(LayeredVpnService.traffic==1&&LayeredVpnService.current.exit.equals(f.exit.id),"selected external used another native path");
   AndroidExternalNodeStatistics.Record saved=AndroidExternalNodeStatistics.load(f.activity,f.exit.id);check(saved!=null&&saved.median==2&&saved.entryKind.equals(shape.equals("router")?"router-vpn":shape.equals("ordinary")?"external":"direct"),"durable external path identity or statistics changed");
   String text=saved.detail();check(text.contains("50-sample routed HTTPS")&&text.contains("after")&&text.contains("not ICMP RTT")&&text.contains("direct TCP"),"routed response was labelled as direct/ICMP RTT");
   check(Arrays.equals(original,Files.readAllBytes(f.exitFile().toPath()))&&Arrays.equals(router,Files.readAllBytes(f.router.file.toPath())),"benchmark mutated private source credentials or policy");
   check(!new String(f.saved()).contains("private-external-secret")&&!new String(f.saved()).contains("private-router-token"),"nonsecret historical store leaked credentials");
   f.activity.saved();check(f.activity.title.contains("Saved HTTPS")&&f.activity.message.contains("50-sample routed HTTPS"),"saved external selection borrowed Router statistics");
   f.hold();Callback retest=f.run();await(LayeredVpnService.drainEntered,"Retest did not create its own retained native request");byte[] previous=f.saved();f.release();retest.joined();check(retest.error==null&&!Arrays.equals(previous,f.saved()),"Retest did not atomically replace complete historical result");
  }
 }
 static void failures(Path root)throws Exception{
  for(String fault:List.of("cancel","source","entry-source","owner","generation","proof","emergency","selection","receipt","native","execution","save"))try(Fixture f=new Fixture(root,"router")){
   f.baseline();byte[] before=f.saved();f.hold();Callback cb=f.run();await(LayeredVpnService.drainEntered,"failed request did not hold its original native drain");
   if(fault.equals("cancel"))f.benchmark.cancel();
   if(fault.equals("source")){String raw=Files.readString(f.exitFile().toPath()).replace("private-external-secret","changed-external-secret");AndroidPrivateFileStore.write(f.exitFile(),raw.getBytes(java.nio.charset.StandardCharsets.UTF_8),512*1024);}
   if(fault.equals("entry-source"))AndroidPrivateFileStore.write(f.router.file,(Files.readString(f.router.file.toPath())+"\n").getBytes(java.nio.charset.StandardCharsets.UTF_8),AndroidNodeStore.MAX_BUNDLE);
   if(fault.equals("owner"))AndroidHomeStateStore.begin(f.activity,"replacement","wg","wg","other");
   if(fault.equals("generation"))AndroidHomeStateStore.advancePathGeneration(f.activity);
   if(fault.equals("proof"))AndroidHomeStateStore.failedPreservingOwnership(f.activity,"proof expired");
   if(fault.equals("emergency"))AndroidHomeStateStore.warning(f.activity,"Emergency Disconnect requested; retained owner");
   if(fault.equals("selection"))f.activity.getSharedPreferences("routervpn_home_state_v1",0).edit().putString("active_external_id","other").apply();
   if(fault.equals("receipt"))f.runtime.replaceFixtureReceipt();if(fault.equals("native"))LayeredVpnService.valid=false;if(fault.equals("execution"))f.runtime.selected="local";
   if(fault.equals("save"))android.system.Os.failTarget=f.file().getAbsolutePath();
   check(Arrays.equals(before,f.saved())&&cb.done.getCount()==1&&AndroidMTUMeasurementGate.held(),"failed/cancelled request displaced result before drain: "+fault);
   f.release();cb.joined();check(cb.error!=null&&cb.result==null&&Arrays.equals(before,f.saved()),"invalid or cancelled benchmark replaced saved result: "+fault);
   check(LayeredVpnService.current.drained,"failed benchmark returned before its original native workers drained");
  }
 }
 static void invalidResults(Path root)throws Exception{
  for(String fault:List.of("wrong-node","private","entry","not-ready","typed-ready","transfer","49","attempts","failed","typed-count","endpoint","icmp","negative","order","trimmed","status-failure","stage-cancelled","stage-invalidated"))try(Fixture f=new Fixture(root,"direct")){
   f.baseline();byte[] before=f.saved();LayeredVpnService.fault=fault;Callback cb=f.run();cb.joined();check(cb.error!=null&&cb.result==null&&Arrays.equals(before,f.saved()),"malformed native benchmark was saved: "+fault);
  }
 }
 static void preflightAndHistorical(Path root)throws Exception{
  for(String fault:List.of("selected-other","source","entry","no-native","mtu"))try(Fixture f=new Fixture(root,"router")){
   if(fault.equals("source"))AndroidPrivateFileStore.write(f.exitFile(),Files.readString(f.exitFile().toPath()).replace("private-external-secret","updated-key").getBytes(java.nio.charset.StandardCharsets.UTF_8),512*1024);
   if(fault.equals("entry"))AndroidPrivateFileStore.write(f.router.file,(Files.readString(f.router.file.toPath())+"\n").getBytes(java.nio.charset.StandardCharsets.UTF_8),AndroidNodeStore.MAX_BUNDLE);
   if(fault.equals("no-native"))LayeredVpnService.valid=false;if(fault.equals("mtu"))LayeredVpnService.quiesceFailed=true;
   Callback cb=new Callback();f.benchmark.run(fault.equals("selected-other")?"other":f.exit.id,cb);cb.joined();check(cb.error!=null&&LayeredVpnService.traffic==0&&!f.file().exists(),"preflight failure started native benchmark: "+fault);
  }
  try(Fixture f=new Fixture(root,"router")){
   f.baseline();check(AndroidExternalNodeStatistics.load(f.activity,f.entry.id)==null,"selected external inherited another node's saved response");
   byte[] before=f.saved();AndroidHomeStateStore.disconnected(f.activity);check(AndroidExternalNodeStatistics.load(f.activity,f.exit.id)!=null,"historical result incorrectly pretended to require a current native path");
   AndroidStandardExitStore.Entry other=f.exits.get(f.entry.id);other.name="unrelated metadata";f.exits.save(other);check(AndroidExternalNodeStatistics.load(f.activity,f.exit.id)!=null,"unrelated node changed historical result identity");
   AndroidPrivateFileStore.write(f.router.file,(Files.readString(f.router.file.toPath())+"\n").getBytes(java.nio.charset.StandardCharsets.UTF_8),AndroidNodeStore.MAX_BUNDLE);check(AndroidExternalNodeStatistics.load(f.activity,f.exit.id)==null&&Arrays.equals(before,f.saved()),"reimported entry retained stale usable statistics or destroyed history");
  }
  try(Fixture f=new Fixture(root,"direct")){
   f.baseline();byte[] before=f.saved();String corrupted=new String(before).replace("\"schema\":1","\"schema\":1,\"schema\":1");AndroidPrivateFileStore.write(f.file(),corrupted.getBytes(java.nio.charset.StandardCharsets.UTF_8),192*1024);byte[] corrupt=f.saved();Callback cb=f.run();cb.joined();check(cb.error!=null&&Arrays.equals(corrupt,f.saved()),"corrupt historical store was silently discarded");
  }
 }

 static void dialogLifecycle(Path root)throws Exception{
  try(Fixture f=new Fixture(root,"direct")){
   f.baseline();byte[] previous=f.saved();f.hold();AndroidExternalBenchmarkDialog ui=new AndroidExternalBenchmarkDialog(f.activity,f.exit.id);ui.show();android.app.AlertDialog dialog=android.app.AlertDialog.last;
   await(LayeredVpnService.drainEntered,"visible benchmark did not invoke the selected captured measurement");check(dialog.isShowing()&&!dialog.getButton(-1).isEnabled(),"Retest remained enabled while the original native worker was draining");dialog.dismiss();check(LayeredVpnService.current.cancels>0&&AndroidMTUMeasurementGate.held(),"dismissing external benchmark did not cancel and retain original drain");f.release();long deadline=System.nanoTime()+4_000_000_000L;while(AndroidMTUMeasurementGate.held()&&System.nanoTime()<deadline)Thread.sleep(2);check(!AndroidMTUMeasurementGate.held()&&Arrays.equals(previous,f.saved()),"dismissed external benchmark saved a late result or leaked its hold");
  }
  try(Fixture f=new Fixture(root,"direct")){
   f.hold();AndroidExternalBenchmarkDialog ui=new AndroidExternalBenchmarkDialog(f.activity,f.exit.id);ui.show();android.app.AlertDialog dialog=android.app.AlertDialog.last;await(LayeredVpnService.drainEntered,"visible benchmark did not start");f.release();long deadline=System.nanoTime()+4_000_000_000L;String detail="";
   // The Android UI thread serializes this callback. Its immediate fixture
   // double runs on the worker, so observe both callback writes together.
   do{detail=((android.widget.TextView)((android.widget.ScrollView)dialog.view).children.get(0)).getText().toString();if(dialog.getButton(-1).isEnabled()&&detail.contains("Saved 50-sample routed HTTPS"))break;Thread.sleep(2);}while(System.nanoTime()<deadline);
   check(dialog.getButton(-1).isEnabled()&&detail.contains("Saved 50-sample routed HTTPS"),"visible complete benchmark did not display its actual saved result");byte[] previous=f.saved();f.hold();check(dialog.getButton(-1).performClick(),"Retest handler was not attached");await(LayeredVpnService.drainEntered,"Retest bypassed the actual native request");f.release();deadline=System.nanoTime()+4_000_000_000L;while(!dialog.getButton(-1).isEnabled()&&System.nanoTime()<deadline)Thread.sleep(2);check(dialog.getButton(-1).isEnabled()&&!Arrays.equals(previous,f.saved()),"Retest did not publish a fresh complete request");ui.close();check(!dialog.isShowing(),"Activity cleanup retained external benchmark dialog");
  }
 }
 public static void main(String[] args)throws Exception{Path root=Path.of(args[0]);Files.createDirectories(root);ordinary(root);failures(root);invalidResults(root);preflightAndHistorical(root);dialogLifecycle(root);System.out.println("Android external 50-sample statistics: "+checks+" checks; exact source/path, native drain, cancellation, durable private storage, Retest and selected-node dispatch");}
}'''


def verify_shared_bridge():
    """Compile and call every shipping public wrapper unchanged against the
    actual shared service; native Box creation remains the separate gate."""
    source = (ROOT / 'mobile/routervpn_hop_measurement.go.tmpl').read_text()
    wrapper = U.S.block(source, 'type RouterHopMeasurement struct') + '\n'
    for name in ('Start', 'StartLatency', 'Cancel', 'Drain', 'StatusJSON', 'Close', 'NetworkChanged'):
        wrapper += U.S.block(source, 'func (m *RouterHopMeasurement) ' + name + '(') + '\n'
    test = r'''package libbox
import("context";"encoding/json";"errors";"net";"strings";"testing";"time";"router-vpn/internal/hopmeasure")
type bridgeEngine struct{started chan struct{}}
func(e *bridgeEngine)Identity()string{return "exact-native-owner"}
func(e *bridgeEngine)Dial(ctx context.Context,tag,address string)(net.Conn,error){
 if tag!="custom-exit"||address!=hopmeasure.PublicAddress{return nil,errors.New("wrong captured route")};close(e.started);<-ctx.Done();return nil,ctx.Err()
}
func TestShippingExternalLatencyBridge(t *testing.T){
 engine:=&bridgeEngine{started:make(chan struct{})};service,err:=hopmeasure.New(engine,[]hopmeasure.Hop{{ID:"exit-owned",Role:"exit",Kind:"public-path",Tag:"custom-exit"}});if err!=nil{t.Fatal(err)}
 bridge:=&RouterHopMeasurement{service};id:=strings.Repeat("a",32)
 if bridge.StartLatency("invalid","exit-owned")==nil||bridge.StartLatency(id,"other")==nil||bridge.Start(id,0)==nil{t.Fatal("public wrapper relaxed request, exit or transfer bounds")}
 if err:=bridge.StartLatency(id,"exit-owned");err!=nil{t.Fatal(err)}
 select{case<-engine.started:case<-time.After(time.Second):t.Fatal("shipping latency wrapper did not reach the actual sealed native route")}
 bridge.Cancel(id);if err:=bridge.Drain(id);err!=nil{t.Fatal(err)}
 var status hopmeasure.Status;if err:=json.Unmarshal([]byte(bridge.StatusJSON()),&status);err!=nil{t.Fatal(err)}
 if status.Request!=id||!status.Complete||!status.Drained||len(status.Results)!=0{t.Fatal("public wrapper lost cancellation or actual drain",status)}
 bridge.NetworkChanged();if bridge.StartLatency(strings.Repeat("b",32),"exit-owned")==nil{t.Fatal("network-invalidated wrapper started another request")}
 if err:=bridge.Close();err!=nil{t.Fatal(err)}
}
'''
    with tempfile.TemporaryDirectory(prefix='.external-statistics-native-', dir=ROOT) as directory:
        work = Path(directory)
        (work / 'bridge.go').write_text('package libbox\nimport("errors";"router-vpn/internal/hopmeasure")\n' + wrapper)
        (work / 'bridge_test.go').write_text(test)
        subprocess.run(['go', 'test', '-race', '-count=1', str(work)], cwd=ROOT, check=True, timeout=120)


def main():
    jar = Path(os.environ.get('ANDROID_JSON_JAR', '/usr/share/java/com.android.json.jar'))
    if not jar.is_file():
        raise RuntimeError('Android JSON and JDK are required')
    verify_shared_bridge()
    ui, boundaries = U.sources()
    ui['android/app/AlertDialog.java'] = ui['android/app/AlertDialog.java'].replace('public void show(){', 'public boolean isShowing(){return showing;}public void show(){')
    ui['android/widget/TextView.java'] = ui['android/widget/TextView.java'][:-1] + 'public void setTextIsSelectable(boolean value){} }'
    ui['android/system/Os.java'] = ui['android/system/Os.java'].replace('public static volatile String holdTarget="";', 'public static volatile String holdTarget="",failTarget="";').replace('public static void rename(String a,String b)throws Exception{', 'public static void rename(String a,String b)throws Exception{if(b.equals(failTarget))throw new IOException("controlled atomic save failure");')
    # Keep the selected source and runtime validations byte-for-byte identical;
    # the extra fixture method stands in only for previously proved native adoption.
    source = (JAVA / 'AndroidStandardExitRuntime.java').read_text()
    receipt = RUNTIME.replace(' // SHIPPING_MEASUREMENT_SOURCE', U.S.block(source, '    static final class MeasurementSource'))
    receipt = receipt.replace(' // SHIPPING_CAPTURE', U.S.block(source, '    synchronized MeasurementSource captureMeasurementSource('))
    receipt = receipt.replace(' // SHIPPING_REQUIRE', U.S.block(source, '    synchronized void requireMeasurementSource('))
    runtime = U.S.block(boundaries, 'final class AndroidStandardExitRuntime')
    boundaries = U.S.replace_class(boundaries, 'AndroidStandardExitRuntime', runtime[:-1] + receipt + '}')
    policy = U.S.block(boundaries, 'final class AndroidExternalPolicy')
    boundaries = U.S.replace_class(boundaries, 'AndroidExternalPolicy', policy[:-1] + U.S.block((JAVA / 'AndroidExternalPolicy.java').read_text(), '    static String entryDigest(') + '}')
    # The Router-only saved-statistics branch remains an executable rejection
    # boundary; selecting an external node must never dispatch to it.
    boundaries = boundaries.replace('boolean eligible(){return false;}', 'String detail(){throw new AssertionError("external selection used Router statistics");}boolean eligible(){return false;}')
    with tempfile.TemporaryDirectory(prefix='routervpn-external-statistics-') as directory, tempfile.TemporaryDirectory(prefix='.external-statistics-json-', dir=ROOT) as validator_directory:
        root = Path(directory)
        validator_source = Path(validator_directory) / 'main.go'
        validator_source.write_text(U.S.PRIVATE_JSON_GO.replace('4097', '524289').replace('4096', '524288'))
        validator = root / 'private-json'
        subprocess.run(['go', 'build', '-o', str(validator), str(validator_source)], cwd=ROOT, check=True, timeout=120)
        for name, text in ui.items():
            file = root / name
            file.parent.mkdir(parents=True, exist_ok=True)
            file.write_text(text)
        app = root / 'com/eabusham/routervpn'
        app.mkdir(parents=True)
        (app / 'Boundaries.java').write_text(boundaries)
        (app / 'LayeredVpnService.java').write_text(NATIVE)
        (app / 'StatisticsActivity.java').write_text(ACTIVITY.replace(' // SHIPPING_SAVED', U.S.block((JAVA / 'ProductActivity.java').read_text(), '    private void showSavedStatistics(')))
        (app / 'ExternalStatisticsTest.java').write_text(HARNESS)
        names = ('AndroidPrivateFileStore', 'AndroidNodeUsage', 'AndroidHomeStateStore', 'AndroidNodeStore', 'AndroidStandardExitStore', 'AndroidProfileSelection', 'AndroidUnifiedNodeCatalog', 'AndroidConnectionSelection', 'AndroidUnifiedConnectionController', 'AndroidNumericAddress', 'AndroidMTUMeasurementGate', 'AndroidNativeHopMeasurement', 'AndroidExternalNodeStatistics', 'AndroidExternalNodeBenchmark', 'AndroidExternalBenchmarkDialog')
        for name in names:
            (app / (name + '.java')).write_bytes((JAVA / (name + '.java')).read_bytes())
        compile = ['javac', '--release', '17', '-encoding', 'UTF-8', '-proc:none', '-cp', str(jar), '-d', str(root / 'classes'), *map(str, root.rglob('*.java'))]
        run = ['java', '--add-opens=java.base/java.io=ALL-UNNAMED', '-Dfixture.privatejson=' + str(validator), '-cp', os.pathsep.join((str(root / 'classes'), str(jar))), 'com.eabusham.routervpn.ExternalStatisticsTest', str(root / 'data')]
        subprocess.run(compile, check=True, timeout=45)
        subprocess.run(run, check=True, timeout=90)
        controls = (
            ('AndroidExternalNodeStatistics.java', 'integer(stats,"samples")!=50', 'integer(stats,"samples")<1', 'malformed native benchmark was saved: 49', 1),
            ('AndroidExternalNodeStatistics.java', '!source.path.home.activeExternalId.equals(text(row,"node_id"))', 'false', 'malformed native benchmark was saved: wrong-node', 1),
            ('AndroidExternalNodeStatistics.java', '!MEASUREMENT.equals(text(benchmark,"measurement"))', 'false', 'malformed native benchmark was saved: icmp', 1),
            ('AndroidExternalNodeStatistics.java', '!"complete".equals(text(status,"stage"))', 'false', 'malformed native benchmark was saved: stage-cancelled', 1),
        )
        for name, old, new, assertion, count in controls:
            file = app / name
            original = file.read_text()
            assert original.count(old) == count, (name, old)
            file.write_text(original.replace(old, new))
            subprocess.run(compile, check=True, timeout=45, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            broken = subprocess.run(run, capture_output=True, text=True, timeout=90)
            file.write_text(original)
            assert broken.returncode != 0 and assertion in broken.stderr, assertion + '\n' + broken.stdout + broken.stderr
            print('External statistics negative control rejected:', assertion)
        captured_files = {name: (app / name).read_text() for name in ('AndroidExternalNodeStatistics.java', 'AndroidExternalNodeBenchmark.java')}
        try:
            # Remove both redundant publication checks. The actual filesystem
            # mutation must now reach (and be caught by) the saved-byte witness.
            for name, source in captured_files.items():
                assert source.count('source.requireCurrent();') == 1, name
                (app / name).write_text(source.replace('source.requireCurrent();', '/* broken original source readback */'))
            subprocess.run(compile, check=True, timeout=45, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            broken = subprocess.run(run, capture_output=True, text=True, timeout=90)
            assert broken.returncode != 0 and 'invalid or cancelled benchmark replaced saved result: source' in broken.stderr, broken.stdout + broken.stderr
            print('External statistics negative control rejected: exact source readback before durable publication')
        finally:
            for name, source in captured_files.items():
                (app / name).write_text(source)


if __name__ == '__main__':
    main()
