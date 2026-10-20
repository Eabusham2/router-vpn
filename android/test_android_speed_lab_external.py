#!/usr/bin/env python3
"""Execute the shipping Speed Lab external transaction with controlled boundaries."""
from pathlib import Path
import importlib.util
import os
import re
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
JAVA = ROOT / "android/app/src/main/java/com/eabusham/routervpn"
spec = importlib.util.spec_from_file_location("speed_lab_native_modes", ROOT / "android/test_android_external_permission.py")
P = importlib.util.module_from_spec(spec)
spec.loader.exec_module(P)

BOUNDARIES = r'''package com.eabusham.routervpn;
import android.app.Activity;import java.io.*;import java.util.*;import java.nio.file.*;import java.util.function.*;
final class AndroidPrivateFileStore{static byte[] read(File f,int max)throws Exception{byte[] b=Files.readAllBytes(f.toPath());if(b.length==0||b.length>max)throw new IllegalArgumentException("bounded private capture required");return b;}}
final class AndroidTorProfile{static String digest(byte[] b)throws Exception{return java.util.HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256").digest(b));}}
final class NativeSingBoxController{
 // PRODUCTION_NATIVE_PREDICATES
}
final class AndroidNativeCompositeProfile{
 // PRODUCTION_COMPOSITE_PREDICATE
}
final class AndroidNodeStore{
 static final int MAX_BUNDLE=32*1024*1024;static final List<Node> saved=new ArrayList<>();
 static final class Node{final String id,name;final File file;Node(String id,File f){this.id=id;name=id;file=f;}}
 AndroidNodeStore(Activity a){}List<Node> list(){return new ArrayList<>(saved);}
}
final class AndroidStandardExitStore{
 static final class Entry{String id="exit",protocol="openvpn",secret="captured-private-key";}
 static Entry copy(Entry x){Entry e=new Entry();e.id=x.id;e.protocol=x.protocol;e.secret=x.secret;return e;}
 static void validate(Entry e){if(e==null||e.id.isEmpty())throw new IllegalArgumentException("invalid external profile");}
}
final class AndroidHomeStateStore{
 static final class Snapshot{boolean connected;String sessionId="off",phase="off",pathProof="pending",logicalMode="",activeExternalId="",activeExternalProtocol="",activeEntryId="",activeEntryMode="",activeExitId="";}
 static Snapshot value=new Snapshot();static Snapshot snapshot(Activity a){return value;}
}
final class LayeredVpnService{static Consumer<Throwable> quiesce;static int calls;static void quiesceMTUForSpeedLab(Consumer<Throwable> cb){calls++;quiesce=cb;}}
final class AndroidUnifiedConnectionController{
 interface Callback{void progress(String m);void finished(boolean ok,String m);default void owned(String session){}}
 int starts,broadStops,ownedStops,ownedRequests;String entryMode="",requestedCleanup="";boolean direct,busy,holdCleanup;AndroidNodeStore.Node entry;AndroidStandardExitStore.Entry external;Callback pending,cleanup;
 boolean isActiveOrTransitioning(){return busy||AndroidHomeStateStore.value.connected;}
 void connectExternal(AndroidNodeStore.Node node,AndroidStandardExitStore.Entry exit,boolean d,String mode,Callback cb){starts++;entry=node;external=exit;direct=d;entryMode=mode;pending=cb;}
 void connectNode(AndroidNodeStore.Node n,String mode,List<String> layers,Callback cb){starts++;pending=cb;}
 void connectMultihop(AndroidNodeStore.Node a,AndroidNodeStore.Node b,String mode,String execution,String entry,Callback cb){starts++;pending=cb;}
 void disconnect(Callback cb){broadStops++;AndroidHomeStateStore.value=new AndroidHomeStateStore.Snapshot();cb.finished(true,"broad native stop");}
 void disconnectExternal(String session,Callback cb){ownedRequests++;requestedCleanup=session;cleanup=cb;if(holdCleanup)return;completeCleanup();}
 void completeCleanup(){if(!requestedCleanup.isEmpty()&&requestedCleanup.equals(AndroidHomeStateStore.value.sessionId)){ownedStops++;AndroidHomeStateStore.value=new AndroidHomeStateStore.Snapshot();}cleanup.finished(true,"captured external stop");}
 void prove(String id){AndroidHomeStateStore.Snapshot s=new AndroidHomeStateStore.Snapshot();s.connected=true;s.sessionId=id;s.phase="connected";s.pathProof="passed";s.logicalMode="external";s.activeExternalId=external.id;s.activeExternalProtocol=external.protocol;s.activeEntryId=direct?"":entry.id;s.activeEntryMode=direct?"external":entryMode;AndroidHomeStateStore.value=s;pending.owned(id);pending.finished(true,"proved");}
}
final class AndroidSpeedLab{
 interface Callback{void finished(Result result,Throwable error);}static final class Result{}
 // PRODUCTION_DURATION_POLICY
 static double round(double n){return n;}
 static Callback pending;static int starts;static String timing;static double min,max;
 AndroidSpeedLab(Activity a){}void run(String mode,double low,double high,Callback cb){starts++;timing=mode;min=low;max=high;pending=cb;}
}
final class AndroidNativeHopMeasurement{
 interface Callback{void progress(String status);void finished(String status,Throwable error);}
 void run(Object lease,Callback cb){if(!AndroidMTUMeasurementGate.owns(lease))throw new AssertionError("native hops lost outer MTU hold");cb.finished("native measured paths",null);}
}
final class AndroidHopMeasurementDialog{static String renderStatus(String s){return s;}}
final class AndroidSpeedLabHopMeter{
 static final class Hop{}interface Callback{void finished(List<Hop> hops,Throwable error);}AndroidSpeedLabHopMeter(Activity a){}
 void measure(AndroidNodeStore.Node a,AndroidNodeStore.Node b,Callback cb){cb.finished(Collections.emptyList(),null);}
}
'''

HARNESS = r'''package com.eabusham.routervpn;
import android.app.Activity;import java.nio.file.*;import java.util.*;import java.util.function.*;
public class SpeedLabExternalTest{
 // ALL_CAPTURED_MODES
 static int checks;static void check(boolean ok,String message){checks++;if(!ok)throw new AssertionError(message);}
 static final class Result implements AndroidSpeedLabController.Callback{int completions;Throwable error;AndroidSpeedLab.Result result;public void progress(String m){}public void finished(AndroidSpeedLab.Result r,Throwable e){completions++;result=r;error=e;}}
 static final class Fixture{
  final Activity activity=new Activity();final AndroidUnifiedConnectionController connection=new AndroidUnifiedConnectionController();final AndroidSpeedLabController controller=new AndroidSpeedLabController(activity,connection);final Result result=new Result();final AndroidSpeedLabController.Request request=new AndroidSpeedLabController.Request();final Path file;
  Fixture(Path root)throws Exception{check(!AndroidMTUMeasurementGate.held(),"previous transaction leaked its MTU hold");AndroidHomeStateStore.value=new AndroidHomeStateStore.Snapshot();AndroidSpeedLab.starts=0;AndroidSpeedLab.pending=null;LayeredVpnService.calls=0;LayeredVpnService.quiesce=null;file=Files.createTempFile(root,"speed-entry-",".json");Files.writeString(file,"captured full entry");request.scope="temporary";request.topology="external";request.externalDirect=false;request.entry=new AndroidNodeStore.Node("entry",file.toFile());request.entryMode="max-quic-awg";request.standardExit=new AndroidStandardExitStore.Entry();request.durationMode="custom";request.minSeconds=2;request.maxSeconds=3;}
  void run(){controller.run(request,result);}void drain(){LayeredVpnService.quiesce.accept(null);}void finish(){AndroidSpeedLab.pending.finished(new AndroidSpeedLab.Result(),null);}
 }
 static void allEntries(Path root)throws Exception{
  for(String protocol:new String[]{"wireguard","amneziawg","socks5","http","https","shadowsocks","hysteria2","openvpn","tor","tor-bridge"})for(String mode:ALL){
   Fixture f=new Fixture(root);f.request.entryMode=mode;f.request.standardExit.protocol=protocol;String secret=f.request.standardExit.secret;f.run();check(f.connection.starts==0&&AndroidMTUMeasurementGate.held(),"temporary graph started before MTU drain");
   f.request.entryMode="wg";f.request.standardExit.secret="changed-caller-key";f.request.standardExit.protocol="http";f.request.minSeconds=7;f.request.topology="system-direct";f.drain();
   check(f.connection.starts==1&&f.connection.entryMode.equals(mode)&&f.connection.external.protocol.equals(protocol)&&f.connection.external.secret.equals(secret),"Speed Lab dropped captured external credentials or selected entry");
   f.connection.prove("test-owned");check(AndroidSpeedLab.starts==1&&AndroidSpeedLab.min==2&&AndroidSpeedLab.max==3,"measurement did not use captured timing and proven path");f.finish();
   check(f.result.completions==1&&f.result.error==null&&!f.controller.isRunning()&&!AndroidMTUMeasurementGate.held(),"test transaction did not finish cleanly");check(f.connection.broadStops==0&&f.connection.ownedStops==1&&f.connection.requestedCleanup.equals("test-owned"),"temporary external cleanup escaped its exact Home owner");
  }
  Fixture direct=new Fixture(root);direct.request.externalDirect=true;direct.request.entry=null;direct.request.entryMode="";direct.run();direct.drain();direct.connection.prove("direct-owned");direct.finish();check(direct.result.error==null&&direct.connection.ownedStops==1,"direct temporary external path acquired an entry");
 }
 static void staleAndDenied(Path root)throws Exception{
  for(String reason:new String[]{"entry","removed","busy","mtu-failed","mode"}){Fixture f=new Fixture(root);if(reason.equals("mode"))f.request.entryMode="";f.run();if(reason.equals("entry"))Files.writeString(f.file,"changed profile");if(reason.equals("removed"))Files.delete(f.file);if(reason.equals("busy"))f.connection.busy=true;if(!reason.equals("mode")){if(reason.equals("mtu-failed"))LayeredVpnService.quiesce.accept(new IllegalStateException("MTU drain incomplete"));else f.drain();}check(f.connection.starts==0&&f.result.error!=null&&f.result.completions==1&&!AndroidMTUMeasurementGate.held(),"changed preflight input started a path: "+reason);}
  Fixture denied=new Fixture(root);denied.run();denied.drain();AndroidHomeStateStore.Snapshot newer=new AndroidHomeStateStore.Snapshot();newer.connected=true;newer.sessionId="newer-user-owner";AndroidHomeStateStore.value=newer;denied.connection.pending.finished(false,"permission denied");check(denied.result.error!=null&&denied.connection.ownedStops==0&&denied.connection.broadStops==0&&AndroidHomeStateStore.value==newer,"denied temporary permission disconnected a newer session");
  for(boolean replace:new boolean[]{false,true}){Fixture f=new Fixture(root);f.run();f.drain();f.connection.prove("old-test");AndroidHomeStateStore.Snapshot s=AndroidHomeStateStore.value;if(replace){s=new AndroidHomeStateStore.Snapshot();s.connected=true;s.sessionId="newer-session";AndroidHomeStateStore.value=s;}else s.activeEntryMode="reality-xhttp";f.finish();check(f.result.error!=null&&f.result.result==null,"stale external path kept a speed result");if(replace)check(f.connection.ownedStops==0&&f.connection.broadStops==0&&AndroidHomeStateStore.value==s,"old speed result disconnected a replacement");}
 }
 static void callbacks(Path root)throws Exception{
  Fixture f=new Fixture(root);f.run();Consumer<Throwable> oldDrain=LayeredVpnService.quiesce;f.drain();AndroidUnifiedConnectionController.Callback oldConnect=f.connection.pending;f.connection.prove("first");AndroidSpeedLab.Callback oldMeter=AndroidSpeedLab.pending;oldDrain.accept(new IllegalStateException("duplicate late drain"));check(f.result.completions==0&&f.controller.isRunning(),"duplicate MTU callback finalized active work");oldConnect.finished(true,"duplicate connected");check(AndroidSpeedLab.starts==1,"duplicate proof started another meter");f.finish();check(f.result.completions==1,"first test not finished");
  Result second=new Result();f.controller.run(f.request,second);Consumer<Throwable> next=LayeredVpnService.quiesce;oldConnect.finished(false,"old failure");oldMeter.finished(new AndroidSpeedLab.Result(),null);oldDrain.accept(null);check(second.completions==0&&f.controller.isRunning()&&AndroidMTUMeasurementGate.held(),"stale callback released a newer MTU transaction");next.accept(null);f.connection.prove("second");f.finish();check(second.completions==1&&second.error==null&&!AndroidMTUMeasurementGate.held(),"newer transaction did not retain its own completion");
 }
 public static void main(String[]args)throws Exception{Path root=Path.of(args[0]);allEntries(root);staleAndDenied(root);callbacks(root);System.out.println("Android external Speed Lab: "+checks+" checks; all19 modes, frozen inputs, stale callbacks and captured cleanup");}
}
'''


def main():
    if not shutil.which("javac"):
        raise RuntimeError("JDK required for shipping Speed Lab transaction test")
    native = (JAVA / "NativeSingBoxController.java").read_text()
    predicates = []
    for name in ("nativeMultihopEntry", "nativeWireGuardFamily", "nativeNaiveFamily", "nativePQFamily"):
        match = re.findall(r"(?ms)^    static boolean " + name + r"\(String mode\) \{\n.*?^    \}", native)
        assert len(match) == 1
        predicates.append(match[0])
    composite = re.findall(r"(?ms)^    static boolean isMode\(String mode\) \{\n.*?^    \}", (JAVA / "AndroidNativeCompositeProfile.java").read_text())[0]
    speed = (JAVA / "AndroidSpeedLab.java").read_text()
    duration = speed[speed.index("    static final class DurationPolicy"):speed.index("    static final class Latency")]
    boundaries = BOUNDARIES.replace(" // PRODUCTION_NATIVE_PREDICATES", "\n".join(predicates)).replace(" // PRODUCTION_COMPOSITE_PREDICATE", composite).replace(" // PRODUCTION_DURATION_POLICY", duration)
    modes = next(line for line in P.T.T.HARNESS.splitlines() if "static final String[] ALL=" in line)
    dialog = (JAVA / "AndroidSpeedLabDialog.java").read_text()
    assert 'q.entryMode=selectedEntryMode()' in dialog
    assert 'connection.supportedNativeEntryModes(selected)' in dialog
    assert 'q.entryMode=new String[]{"wg"' not in dialog
    with tempfile.TemporaryDirectory(prefix="routervpn-speed-external-") as directory:
        root = Path(directory)
        activity = root / "android/app/Activity.java"
        activity.parent.mkdir(parents=True)
        activity.write_text("package android.app;public class Activity{public void runOnUiThread(Runnable r){r.run();}}")
        app = root / "com/eabusham/routervpn"
        app.mkdir(parents=True)
        (app / "Boundaries.java").write_text(boundaries)
        (app / "SpeedLabExternalTest.java").write_text(HARNESS.replace(" // ALL_CAPTURED_MODES", modes))
        for name in ("AndroidSpeedLabController.java", "AndroidMTUMeasurementGate.java"):
            shutil.copyfile(JAVA / name, app / name)
        compile_args = ["javac", "--release", "17", "-encoding", "UTF-8", "-proc:none", "-d", str(root / "classes"), *map(str, root.rglob("*.java"))]
        data = root / "data"
        data.mkdir()
        run_args = ["java", "-cp", str(root / "classes"), "com.eabusham.routervpn.SpeedLabExternalTest", str(data)]
        subprocess.run(compile_args, check=True, timeout=45)
        subprocess.run(run_args, check=True, timeout=25)
        path = app / "AndroidSpeedLabController.java"
        original = path.read_text()
        for old, new, label in (
            ("request.externalDirect,request.entryMode,bridge", 'request.externalDirect,"wg",bridge', "exact selected entry"),
            ("AndroidStandardExitStore.copy(input.standardExit)", "input.standardExit", "frozen external credentials"),
            ("connection.disconnectExternal(externalHome,completed)", "connection.disconnect(completed)", "captured external cleanup"),
        ):
            assert original.count(old) == 1, label
            path.write_text(original.replace(old, new))
            subprocess.run(compile_args, check=True, timeout=45)
            result = subprocess.run(run_args, capture_output=True, text=True, timeout=25)
            assert result.returncode != 0 and "AssertionError" in result.stderr, label + " negative control escaped"
            path.write_text(original)
        print("Android external Speed Lab negative controls: 3 rejected")


if __name__ == "__main__":
    main()
