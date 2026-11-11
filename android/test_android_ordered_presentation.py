#!/usr/bin/env python3
"""Exercise the actual Product worker and Home-bound display publication.

Private stores and presentation/controller source are unchanged. The native
observation boundary blocks deliberately; this is UI ownership evidence, not a
native tunnel or Android rendering acceptance claim.
"""
from pathlib import Path
import os
import subprocess
import tempfile
import test_android_node_usage as U

ROOT, JAVA = U.ROOT, U.JAVA

TEST = r'''
 public static void main(String[] args)throws Exception{
  try(Fixture f=new Fixture(Path.of(args[0]))){
   var source=ordered(f);var home=AndroidHomeStateStore.beginNodeChain(f.activity,source);check(AndroidHomeStateStore.connectedNodeChain(f.activity,home),"display Home setup failed");
   var runtime=AndroidRuntimeRegistry.get(f.activity).nodeChain;runtime.active=new AndroidNodeChainRuntime.ActiveCapture(source,home,orderedProgress(source).toString());
   PresentationObservation.block=true;f.activity.observe();await(PresentationObservation.entered,"Product did not dispatch its worker");
   for(int i=0;i<10;i++)f.activity.observe();
   // Every started Product thread remains alive at the same held observation.
   // Thread.start publishes its live thread before returning, so this inventory
   // does not depend on which thread the scheduler lets reach captureActive first.
   List<Thread> workers=new ArrayList<>();for(Thread thread:Thread.getAllStackTraces().keySet())if(thread.getName().equals("routervpn-ordered-display")&&thread.isAlive())workers.add(thread);
   PresentationObservation.release.countDown();for(Thread thread:workers){thread.join(4000);check(!thread.isAlive(),"Product observation worker did not drain");}
   waitUI(f.activity);f.activity.drainUI();check(workers.size()==1,"Product scheduled overlapping ordered native observations");
   check(f.activity.orderedPresentation!=null&&f.activity.orderedPresentation.live&&!PresentationObservation.onMain,"Product did not publish its worker-produced receipt");
   PresentationObservation.block=false;f.activity.observe();waitUI(f.activity);
   AndroidHomeStateStore.advancePathGeneration(f.activity);f.activity.drainUI();
   check(f.activity.orderedPresentation==null,"slow ordered worker published after a newer Home decision");
   check(f.activity.mapView.ordered.isEmpty()&&!f.activity.mapView.orderedLive,"retired ordered receipt animated the map");
  }
  System.out.println("Android actual Product ordered worker: single observation, off-main native/source capture, queued stale Home publication rejection PASS");
 }
 static void waitUI(UsageActivity a)throws Exception{long end=System.nanoTime()+TimeUnit.SECONDS.toNanos(4);while(a.pendingUI.isEmpty()&&System.nanoTime()<end)Thread.yield();check(!a.pendingUI.isEmpty(),"ordered worker did not finish its captured observation");}
'''


def main():
    ui, boundaries = U.sources()
    boundaries = boundaries.replace('final class AndroidStandardExitRuntime {', 'final class AndroidStandardExitRuntime {' + U.P.UNOWNED_EXTERNAL_RESTORE_SOURCE)
    publication = U.S.block((JAVA / 'AndroidConnectionProfileStore.java').read_text(), '    static void applySelection(')
    boundaries = boundaries.replace('import android.content.Context;', 'import android.content.Context;import android.content.SharedPreferences;').replace('final class AndroidConnectionProfileStore {', 'final class AndroidConnectionProfileStore {' + publication)
    product = (JAVA / "ProductActivity.java").read_text()
    old = "ActiveCapture captureActive(){activeReads++;return active;}"
    assert boundaries.count(old) == 1
    boundaries = boundaries.replace(old, "ActiveCapture captureActive(){activeReads++;PresentationObservation.read();return active;}")
    boundaries += r'''
final class PresentationObservation {
 static volatile boolean block,onMain;static final java.util.concurrent.CountDownLatch entered=new java.util.concurrent.CountDownLatch(1),release=new java.util.concurrent.CountDownLatch(1);
 static void read(){if(Thread.currentThread().getName().equals("main"))onMain=true;entered.countDown();if(block)try{if(!release.await(4,java.util.concurrent.TimeUnit.SECONDS))throw new AssertionError("observation release missing");}catch(InterruptedException e){throw new AssertionError(e);}}
}
'''
    activity = U.ACTIVITY
    activity = activity.replace(' // SHIPPING_EXTERNAL_LATENCY', U.S.block(product, '    private double liveExternalMedian('))
    original = "AndroidOrderedPathPresentation orderedPresentation;AndroidOrderedPathPresentation currentOrderedPresentation(){return orderedPresentation!=null&&orderedPresentation.current(this)?orderedPresentation:null;}"
    assert activity.count(original) == 1
    methods = "\n".join(U.S.block(product, sig) for sig in ("    private boolean orderedPathEnabled(", "    private AndroidOrderedPathPresentation currentOrderedPresentation(", "    private void requestOrderedPresentation("))
    activity = activity.replace(original, r'''
 AndroidOrderedPathPresentation orderedPresentation;boolean orderedPresentationPending;long orderedPresentationGeneration;
 final java.util.concurrent.ConcurrentLinkedQueue<Runnable> pendingUI=new java.util.concurrent.ConcurrentLinkedQueue<>();
 @Override public void runOnUiThread(Runnable r){pendingUI.add(r);}void drainUI(){Runnable r;while((r=pendingUI.poll())!=null)r.run();}
 void observe(){requestOrderedPresentation();}void refreshModeChoices(){}void refreshMultihopSummary(){}
''' + methods)
    callback = U.S.block(product, "    private AndroidUnifiedConnectionController.Callback callback(")
    constants = "\n".join(line for line in product.splitlines() if any(key in line for key in ("private static final String PREFS=", "private static final String MODE_KEY=", "private static final String MULTI_ON=")))
    activity = activity.replace(" // SHIPPING_CALLBACK", callback).replace(" // SHIPPING_MAP_PROJECTION", U.S.block(product, "    private void refreshNodes(")).replace(" // SHIPPING_MAP_CONSTANTS", constants).replace(" // SHIPPING_PREFS", U.S.block(product, "    private SharedPreferences prefs("))
    activity = activity.replace(" // SHIPPING_MAP_MARKER", U.S.block((JAVA / "RouterVpnNodeMapView.java").read_text(), "    static final class Marker")).replace(" // SHIPPING_MAP_VALID", U.S.block((JAVA / "RouterVpnNodeMapView.java").read_text(), "    private boolean valid(Marker m)"))
    # Retain the real-source fixture helpers; only this worker transaction runs.
    harness = U.HARNESS[:U.HARNESS.index("public final class NodeUsageTest")] + "public final class NodeUsageTest {static int checks;\n"
    harness += "\n".join(U.S.block(U.HARNESS, sig) for sig in ("static void check(", "static void await(", "static final class Callback", "static JSONObject bundle(", "static final class Fixture", "static JSONObject orderedBundle(", "static AndroidNodeStore.ChainCapture ordered(", "static JSONObject orderedProgress("))
    harness += TEST + "}"
    jar = Path(os.environ.get("ANDROID_JSON_JAR", "/usr/share/java/com.android.json.jar"))
    with tempfile.TemporaryDirectory(prefix="routervpn-ordered-ui-") as work, tempfile.TemporaryDirectory(prefix=".ordered-ui-json-", dir=ROOT) as go_dir:
        root = Path(work)
        go_source = Path(go_dir) / "main.go"
        go_source.write_text(U.S.PRIVATE_JSON_GO.replace("4097", "98305").replace("4096", "98304"))
        validator = root / "private-json"
        subprocess.run(["go", "build", "-o", str(validator), str(go_source)], cwd=ROOT, check=True, timeout=120)
        for name, source in ui.items():
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(source)
        app = root / "com/eabusham/routervpn"
        app.mkdir(parents=True)
        (app / "Boundaries.java").write_text(boundaries)
        (app / "UsageActivity.java").write_text(activity)
        (app / "NodeUsageTest.java").write_text(harness)
        for name in ("AndroidPrivateFileStore", "AndroidNodeUsage", "AndroidHomeStateStore", "AndroidNodeStore", "AndroidStandardExitStore", "AndroidProfileSelection", "AndroidUnifiedNodeCatalog", "AndroidConnectionSelection", "AndroidUnifiedConnectionController", "AndroidNumericAddress", "AndroidOrderedPathPresentation"):
            (app / (name + ".java")).write_bytes((JAVA / (name + ".java")).read_bytes())
        compile_args = ["javac", "--release", "17", "-encoding", "UTF-8", "-proc:none", "-cp", str(jar), "-d", str(root / "classes"), *map(str, root.rglob("*.java"))]
        (root / "data").mkdir()
        run = ["java", "--add-opens=java.base/java.io=ALL-UNNAMED", "-Dfixture.privatejson=" + str(validator), "-cp", os.pathsep.join((str(root / "classes"), str(jar))), "com.eabusham.routervpn.NodeUsageTest", str(root / "data")]
        subprocess.run(compile_args, check=True, timeout=45)
        subprocess.run(run, check=True, timeout=30)
        for old, new, witness in (("if(orderedPresentationPending||isFinishing()||isDestroyed())return;", "if(isFinishing()||isDestroyed())return;", "Product scheduled overlapping ordered native observations"), ("orderedPresentation=result!=null&&result.current(this)?result:null;", "orderedPresentation=result;", "slow ordered worker published after a newer Home decision")):
            assert activity.count(old) == 1
            (app / "UsageActivity.java").write_text(activity.replace(old, new))
            subprocess.run(compile_args, check=True, timeout=45, capture_output=True)
            result = subprocess.run(run, capture_output=True, text=True, timeout=30)
            if result.returncode == 0 or witness not in result.stderr:
                raise AssertionError("Ordered Product worker mutation missed its defect: " + result.stdout + result.stderr)
            print("Ordered Product worker causal control rejected:", witness)


if __name__ == "__main__":
    main()
