#!/usr/bin/env python3
"""Execute native measurement requests, cancellation/drain, MTU holds and UI."""
from pathlib import Path
import importlib.util
import os
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
JAVA = ROOT / "android/app/src/main/java/com/eabusham/routervpn"
spec = importlib.util.spec_from_file_location("native_hop_widgets", ROOT / "android/test_android_tor_form.py")
T = importlib.util.module_from_spec(spec)
spec.loader.exec_module(T)

BOUNDARIES = r'''package com.eabusham.routervpn;
import java.util.concurrent.*;import java.util.function.*;import org.json.*;
final class AndroidUnifiedConnectionController{boolean connected=true,multihop=true;boolean isConnected(){return connected;}boolean isMultihopConnected(){return connected&&multihop;}}
final class LayeredVpnService{
 static volatile HopMeasurementOwner created;static volatile Consumer<Throwable> quiesce;static boolean autoQuiesce=true,startFails,stale,wrongID,invalidType,drainFailsOnce;static volatile boolean complete=true;static volatile CountDownLatch drainEntered,drainRelease;static int captures;static String exitID,nativeSession,homeSession;static long generation;
 static void reset(){created=null;quiesce=null;autoQuiesce=true;startFails=false;stale=false;wrongID=false;invalidType=false;complete=true;drainFailsOnce=false;drainEntered=null;drainRelease=null;captures=0;}
 static void quiesceMTUForSpeedLab(Consumer<Throwable> cb){quiesce=cb;if(autoQuiesce)cb.accept(null);}
 static HopMeasurementOwner captureHopMeasurement(String id){captures++;created=new HopMeasurementOwner(id);return created;}
 static HopMeasurementOwner captureExternalHopMeasurement(String id,String exit,String nativeID,String home,long pathGeneration){exitID=exit;nativeSession=nativeID;homeSession=home;generation=pathGeneration;return captureHopMeasurement(id);}
 static final class HopMeasurementOwner{
  final String id;volatile boolean began,drained;int starts,cancels,drains;
  HopMeasurementOwner(String id){this.id=id;}
  void start(){if(startFails)throw new IllegalStateException("owner changed before start");began=true;starts++;}
  boolean started(){return began;}
  String status()throws Exception{if(stale)throw new IllegalStateException("old Box replaced");return new JSONObject().put("request_id",wrongID?"f".repeat(32):id).put("stage","measuring").put("complete",complete).put("drained",invalidType?"true":drained).put("results",new JSONArray()).toString();}
  interface Commit{void run()throws Exception;}void commit(Commit c)throws Exception{if(stale)throw new IllegalStateException("owner replaced before UI delivery");c.run();}
  void cancel(){cancels++;}
  void drain()throws Exception{drains++;if(drainEntered!=null)drainEntered.countDown();if(drainFailsOnce&&drains==1)throw new IllegalStateException("native late dial pending");if(drainRelease!=null)drainRelease.await();drained=true;}
 }
}
'''

HARNESS = r'''package com.eabusham.routervpn;
import java.util.concurrent.*;import org.json.*;import android.app.*;import android.widget.*;
public class NativeHopRequestTest{
 static int checks;static void check(boolean ok,String why){checks++;if(!ok)throw new AssertionError(why);}
 static final class Callback implements AndroidNativeHopMeasurement.Callback{
  final CountDownLatch done=new CountDownLatch(1),progressed=new CountDownLatch(1),pendingDrain=new CountDownLatch(1);volatile String result;volatile Throwable error;int completions,commits;boolean failCommit;
  public void progress(String status){progressed.countDown();if(status.contains("draining native"))pendingDrain.countDown();}
  public void commit(LayeredVpnService.HopMeasurementOwner owner,String status){check(owner.drained&&AndroidMTUMeasurementGate.held(),"publication preceded exact native drain or MTU release");commits++;if(failCommit)throw new IllegalStateException("private statistics save failed");}
  public void finished(String status,Throwable failure){result=status;error=failure;completions++;done.countDown();}
  void await()throws Exception{check(done.await(3,TimeUnit.SECONDS),"native request did not complete after drain");}
 }
 static void reset(){check(!AndroidMTUMeasurementGate.held(),"previous native request leaked the MTU hold");LayeredVpnService.reset();}
 static void joined(boolean borrowed)throws Exception{
  reset();LayeredVpnService.drainEntered=new CountDownLatch(1);LayeredVpnService.drainRelease=new CountDownLatch(1);Object lease=borrowed?AndroidMTUMeasurementGate.acquire():null;AndroidNativeHopMeasurement request=new AndroidNativeHopMeasurement();Callback callback=new Callback();request.run(lease,callback);
  check(LayeredVpnService.drainEntered.await(2,TimeUnit.SECONDS),"completed status did not reach native drain");check(callback.done.getCount()==1&&request.isRunning()&&AndroidMTUMeasurementGate.held(),"complete status released MTU before sockets drained");LayeredVpnService.drainRelease.countDown();callback.await();check(callback.error==null&&callback.commits==1&&new JSONObject(callback.result).getBoolean("drained")&&!request.isRunning(),"drained measurement was not returned");
  check(AndroidMTUMeasurementGate.held()==borrowed,"native hop request released someone else's MTU hold");if(borrowed)AndroidMTUMeasurementGate.release(lease);
 }
 static void cancelAndStale()throws Exception{
  for(String reason:new String[]{"cancel","replace","wrong-id","typed-drain","retry"}){
   reset();LayeredVpnService.drainEntered=new CountDownLatch(1);LayeredVpnService.drainRelease=new CountDownLatch(1);LayeredVpnService.complete=!reason.equals("cancel");LayeredVpnService.wrongID=reason.equals("wrong-id");LayeredVpnService.invalidType=reason.equals("typed-drain");LayeredVpnService.drainFailsOnce=reason.equals("retry");
   AndroidNativeHopMeasurement request=new AndroidNativeHopMeasurement();Callback callback=new Callback();request.run(null,callback);
   if(reason.equals("cancel")){check(callback.progressed.await(2,TimeUnit.SECONDS),"request did not start");long began=System.nanoTime();request.cancel();check(System.nanoTime()-began<250000000L,"Cancel blocked on late native cleanup");}
   check(LayeredVpnService.drainEntered.await(2,TimeUnit.SECONDS),"cancelled request did not drain its captured handle");if(reason.equals("replace"))LayeredVpnService.stale=true;if(reason.equals("retry"))check(callback.pendingDrain.await(2,TimeUnit.SECONDS),"failed drain did not retain visible progress");
   check(AndroidMTUMeasurementGate.held()&&callback.done.getCount()==1&&request.isRunning(),"cancel or failed drain released ownership early");LayeredVpnService.drainRelease.countDown();callback.await();check(callback.error!=null&&callback.result==null&&callback.commits==0&&!AndroidMTUMeasurementGate.held(),"cancelled/stale/invalid native results were retained");check(LayeredVpnService.created.drained,"request returned before exact native drain");
  }
 }
 static void preflight()throws Exception{
  for(boolean cancelled:new boolean[]{false,true}){reset();LayeredVpnService.autoQuiesce=false;AndroidNativeHopMeasurement request=new AndroidNativeHopMeasurement();Callback callback=new Callback();request.run(null,callback);if(cancelled)request.cancel();else LayeredVpnService.startFails=true;LayeredVpnService.quiesce.accept(null);callback.await();check(callback.error!=null&&LayeredVpnService.created.starts==0&&LayeredVpnService.created.drains==0&&!AndroidMTUMeasurementGate.held(),"unstarted request acquired a native worker");}
  reset();AndroidNativeHopMeasurement request=new AndroidNativeHopMeasurement();Callback missing=new Callback();request.run(new Object(),missing);missing.await();check(missing.error!=null&&LayeredVpnService.captures==0,"foreign MTU lease reached native owner");
  reset();LayeredVpnService.autoQuiesce=false;Callback first=new Callback();request.run(null,first);Callback duplicate=new Callback();request.run(null,duplicate);duplicate.await();check(duplicate.error!=null&&AndroidMTUMeasurementGate.held(),"duplicate request released another owner");LayeredVpnService.quiesce.accept(null);LayeredVpnService.quiesce.accept(null);first.await();check(first.completions==1&&LayeredVpnService.created.starts==1,"duplicate MTU callback started another native request");
 }

 static void latencyPublication()throws Exception{
  reset();AndroidNativeHopMeasurement request=new AndroidNativeHopMeasurement();Callback cb=new Callback();request.runLatency("selected-external","native-capture","home-capture",17,cb);cb.await();
  check(cb.error==null&&cb.commits==1&&LayeredVpnService.exitID.equals("selected-external")&&LayeredVpnService.nativeSession.equals("native-capture")&&LayeredVpnService.homeSession.equals("home-capture")&&LayeredVpnService.generation==17,"latency API lost selected native/Home generation");
  reset();cb=new Callback();cb.failCommit=true;request.run(null,cb);cb.await();check(cb.error!=null&&cb.result==null&&cb.commits==1&&LayeredVpnService.created.drained&&!AndroidMTUMeasurementGate.held(),"failed durable publication retained a success or leaked native ownership");
  reset();cb=new Callback();request.runLatency("","native","home",1,cb);cb.await();check(cb.error!=null&&cb.commits==0&&LayeredVpnService.captures==0,"empty latency selection reached native handle");
 }
 static JSONObject row()throws Exception{
  JSONObject latency=new JSONObject().put("samples",6).put("min_ms",1).put("median_ms",2).put("average_ms",2).put("p90_ms",3).put("max_ms",3).put("jitter_ms",1);
  JSONObject transfer=new JSONObject().put("bytes",65536).put("seconds",0.5).put("mbps",1.048576).put("loaded_reason","short transfer");
  return new JSONObject().put("node_id","external-exit").put("role","exit").put("kind","public-path").put("label","Tor circuit → Cloudflare edge").put("ready",true).put("idle",latency).put("download",transfer).put("upload",new JSONObject(transfer.toString()));
 }
 static String render(JSONObject row)throws Exception{return AndroidHopMeasurementDialog.renderStatus(new JSONObject().put("stage","complete").put("results",new JSONArray().put(row)).toString());}
 static void rendererAndDialog()throws Exception{
  JSONObject valid=row();String text=render(valid);check(text.contains("Public routed path")&&text.contains("Tor circuit → Cloudflare edge")&&text.contains("Download 1.05 Mbps")&&!text.contains("Private node"),"public Tor path was relabelled as a private node API");
  check(render(new JSONObject(valid.toString()).put("kind","private-node").put("label","Router VPN entry private API")).contains("Private node"),"authenticated entry lost its measurement kind");
  for(String field:new String[]{"kind","label","role","bytes","seconds","rate","samples","ready"}){JSONObject bad=new JSONObject(valid.toString());switch(field){case "kind":bad.put(field,"unowned");break;case "label":bad.put(field,"hidden\nidentity");break;case "role":bad.put(field,"local");break;case "bytes":bad.getJSONObject("download").put("bytes",1);break;case "seconds":bad.getJSONObject("download").put("seconds",0);break;case "rate":bad.getJSONObject("download").put("mbps",100);break;case "samples":bad.getJSONObject("idle").put("samples",0);break;default:bad.put(field,false);}
   String rendered=render(bad);check(rendered.contains("unavailable")&&!rendered.contains("Mbps"),"invalid native metrics were displayed: "+field);}
  reset();LayeredVpnService.autoQuiesce=false;AndroidHopMeasurementDialog dialog=new AndroidHopMeasurementDialog(new Activity(),new AndroidUnifiedConnectionController());dialog.show();check(AlertDialog.last.showing&&AndroidMTUMeasurementGate.held(),"native measurement dialog not wired to owned request");AlertDialog.last.dismiss();check(LayeredVpnService.created.cancels>0,"dialog dismissal did not cancel captured native request");LayeredVpnService.quiesce.accept(null);long deadline=System.nanoTime()+2_000_000_000L;while(AndroidMTUMeasurementGate.held()&&System.nanoTime()<deadline)Thread.sleep(2);check(!AndroidMTUMeasurementGate.held()&&LayeredVpnService.created.starts==0,"dismissed dialog started a new native measurement");
 }

 static final class QueuedActivity extends Activity{
  final java.util.List<Runnable> pending=new java.util.ArrayList<>();
  @Override public synchronized void runOnUiThread(Runnable r){pending.add(r);}
  void flush(){java.util.List<Runnable> work;synchronized(this){work=new java.util.ArrayList<>(pending);pending.clear();}for(Runnable r:work)r.run();}
 }
 static String output(AndroidHopMeasurementDialog d)throws Exception{java.lang.reflect.Field f=AndroidHopMeasurementDialog.class.getDeclaredField("output");f.setAccessible(true);return ((TextView)f.get(d)).getText().toString();}
 static void finishedNative()throws Exception{long end=System.nanoTime()+3_000_000_000L;while(AndroidMTUMeasurementGate.held()&&System.nanoTime()<end)Thread.sleep(2);Thread.sleep(30);check(!AndroidMTUMeasurementGate.held(),"native UI test failed to drain");}
 static void queuedDelivery()throws Exception{
  for(String change:new String[]{"unchanged","replaced","finished","destroyed","dismissed"}){
   reset();QueuedActivity activity=new QueuedActivity();AndroidHopMeasurementDialog dialog=new AndroidHopMeasurementDialog(activity,new AndroidUnifiedConnectionController());dialog.show();finishedNative();String before=output(dialog);
   if(change.equals("replaced"))LayeredVpnService.stale=true;
   if(change.equals("finished"))activity.finished=true;
   if(change.equals("destroyed"))activity.destroyed=true;
   if(change.equals("dismissed"))dialog.close();
   activity.flush();String after=output(dialog);
   if(change.equals("unchanged"))check(after.startsWith("Routed paths:"),"valid retained path did not render");
   else if(change.equals("replaced"))check(after.contains("discarded")&&!after.startsWith("Routed paths:"),"stale native reply reached the UI after replacement");
   else check(before.equals(after),"queued delivery touched an abandoned Activity or dialog: "+change);
   dialog.close();
  }
 }
 static void ordinaryRouterProduct()throws Exception{
  reset();LayeredVpnService.autoQuiesce=false;ProductHopHost host=new ProductHopHost();host.runRoutedHopSpeeds();check(LayeredVpnService.captures==1&&AndroidMTUMeasurementGate.held(),"ordinary Router pair did not enter exactly one retained native request");
  host.closeRoutedHopMeasurement();check(!AlertDialog.last.showing&&LayeredVpnService.created.cancels>0,"Activity cleanup did not close and cancel its owned hop request");LayeredVpnService.quiesce.accept(null);finishedNative();check(LayeredVpnService.created.starts==0,"closed ordinary pair started transfers");
  reset();host=new ProductHopHost();host.connection.connected=false;host.runRoutedHopSpeeds();check(LayeredVpnService.captures==0&&host.notices==1,"disconnected product started a hop measurement");
 }
 public static void main(String[]args)throws Exception{joined(false);joined(true);cancelAndStale();preflight();latencyPublication();rendererAndDialog();queuedDelivery();ordinaryRouterProduct();System.out.println("Android native measurement request: "+checks+" checks; drained MTU ownership, cancellation, replacement, renderer and dialog");}
}'''


def main():
    jar = Path(os.environ.get("ANDROID_JSON_JAR", "/usr/share/java/com.android.json.jar"))
    if not jar.is_file() or not shutil.which("javac"):
        raise RuntimeError("JDK and Android JSON required")
    ui = dict(T.UI)
    ui["android/app/Activity.java"] = ui["android/app/Activity.java"].replace("public boolean finished;", "public boolean finished,destroyed;public boolean isDestroyed(){return destroyed;}")
    product = (JAVA / "ProductActivity.java").read_text()
    start = product.index("    private void runRoutedHopSpeeds(){")
    end = product.index("\n    private void refreshModeChoices", start)
    product_methods = product[start:end].replace("private void", "void")
    for lifecycle in ("onPause", "onDestroy"):
        body = product.split("void " + lifecycle + "(){", 1)[1].split("\n", 1)[0]
        assert "closeRoutedHopMeasurement();" in body, lifecycle + " must cancel its owned dialog"
    assert "activeImportedMultihopEntry" not in product_methods, "ordinary Router hops must use the same captured measurement"
    assert "telemetry.speedTest" not in product_methods, "per-hop display must not transfer both hops twice"
    ui["android/content/SharedPreferences.java"] = "package android.content;public interface SharedPreferences {String getString(String key,String fallback);}"
    ui["android/app/AlertDialog.java"] = ui["android/app/AlertDialog.java"].replace("public void show(){", "public boolean isShowing(){return showing;}public void show(){")
    ui["android/widget/TextView.java"] = ui["android/widget/TextView.java"][:-1] + "public void setTextIsSelectable(boolean selectable){} }"
    with tempfile.TemporaryDirectory(prefix="routervpn-native-hop-request-") as directory:
        root = Path(directory)
        for name, source in ui.items():
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(source)
        app = root / "com/eabusham/routervpn"
        app.mkdir(parents=True)
        (app / "Boundaries.java").write_text(BOUNDARIES)
        (app / "ProductHopHost.java").write_text("package com.eabusham.routervpn;class ProductHopHost extends android.app.Activity { AndroidUnifiedConnectionController connection=new AndroidUnifiedConnectionController();AndroidHopMeasurementDialog routedHopDialog;int notices;void toast(String s){notices++;}" + product_methods + "}")
        (app / "NativeHopRequestTest.java").write_text(HARNESS)
        for name in ("AndroidNativeHopMeasurement.java", "AndroidMTUMeasurementGate.java", "AndroidHopMeasurementDialog.java"):
            shutil.copyfile(JAVA / name, app / name)
        compile_args = ["javac", "--release", "17", "-encoding", "UTF-8", "-proc:none", "-cp", str(jar), "-d", str(root / "classes"), *map(str, root.rglob("*.java"))]
        run_args = ["java", "-cp", os.pathsep.join((str(root / "classes"), str(jar))), "com.eabusham.routervpn.NativeHopRequestTest"]
        subprocess.run(compile_args, check=True, timeout=45)
        subprocess.run(run_args, check=True, timeout=25)
        for name, old, new, label in (
            ("AndroidNativeHopMeasurement.java", "job.owner.drain();joined=true;", "joined=true;", "native drain before completion"),
            ("AndroidNativeHopMeasurement.java", "if(job.releaseLease)AndroidMTUMeasurementGate.release(job.lease);", "AndroidMTUMeasurementGate.release(job.lease);", "borrowed MTU hold"),
            ("AndroidHopMeasurementDialog.java", "owner.commit(()->{if(visible())output.setText(renderStatus(status));});", "if(visible())output.setText(renderStatus(status));", "queued native owner replacement"),
            ("AndroidHopMeasurementDialog.java", '!activity.isFinishing()&&!activity.isDestroyed()&&dialog!=null', 'dialog!=null', "abandoned Activity delivery"),
            ("AndroidHopMeasurementDialog.java", 'Math.abs(bytes*8.0/seconds/1000000.0-rate)<=Math.max(0.000001,rate*0.000001)', "true", "actual transferred Mbps"),
        ):
            path = app / name
            original = path.read_text()
            assert original.count(old) == 1, label
            path.write_text(original.replace(old, new))
            subprocess.run(compile_args, check=True, timeout=45)
            try:
                result = subprocess.run(run_args, capture_output=True, text=True, timeout=8)
                assert result.returncode != 0 and "AssertionError" in result.stderr, label + " negative control escaped"
            except subprocess.TimeoutExpired as timeout:
                assert "AssertionError" in (timeout.stderr or b"").decode(errors="replace"), label + " hung without rejecting"
            path.write_text(original)
        print("Android native measurement request negative controls: 5 rejected")


if __name__ == "__main__":
    main()
