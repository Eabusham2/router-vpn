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
final class AndroidTorProfile{static boolean isTor(String s){return s.equals("tor")||s.equals("tor-bridge");}static String digest(byte[] b)throws Exception{return java.util.HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256").digest(b));}}
final class AndroidExternalPolicy{static boolean supports(String s){return List.of("wireguard","amneziawg","socks5","http","https","shadowsocks","hysteria2","openvpn").contains(s);}static String protocol(String s){return s.equals("http")?"http-connect":s.equals("https")?"https-connect":s;}}
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
 static final Map<String,Entry> saved=new HashMap<>();
 static final class Entry{String id="exit",protocol="openvpn",secret="captured-private-key",policy="captured-policy",expectedPublicIp="8.8.4.4";}
 AndroidStandardExitStore(Activity a){}Entry get(String id){if(!saved.containsKey(id))throw new IllegalStateException("missing saved external source");return copy(saved.get(id));}
 static String snapshot(Entry e){return List.of(e.id,e.protocol,e.secret,e.policy,e.expectedPublicIp).toString();}
 static Entry copy(Entry x){Entry e=new Entry();e.id=x.id;e.protocol=x.protocol;e.secret=x.secret;e.policy=x.policy;e.expectedPublicIp=x.expectedPublicIp;return e;}
 static void validate(Entry e){if(e==null||e.id.isEmpty())throw new IllegalArgumentException("invalid external profile");}
 // Authentication/key/probe compilation is exercised by the real store/native
 // graph suites. This boundary only models execution admission to the controller.
 static void validateExecution(Entry e,boolean entry,String execution){if(!List.of("local","server","auto").contains(execution)||!execution.equals("local")&&(!entry||e.protocol.startsWith("tor")))throw new IllegalArgumentException("unowned execution");}
}
final class AndroidHomeStateStore{
 static final class Snapshot{boolean connected;long pathGeneration;String sessionId="off",phase="off",pathProof="pending",logicalMode="",runtimeMode="",activeNodeId="",activeExternalId="",activeExternalProtocol="",activeEntryId="",activeEntryMode="",activeExitId="";}
 static Snapshot value=new Snapshot();static Snapshot snapshot(Activity a){return value;}
}
final class LayeredVpnService{static Consumer<Throwable> quiesce;static int calls;static void quiesceMTUForSpeedLab(Consumer<Throwable> cb){calls++;quiesce=cb;}static void startAutomaticMTU(){}}
final class AndroidUnifiedConnectionController{
 interface Callback{void progress(String m);void finished(boolean ok,String m);default void owned(String session){}default void superseded(){}default void validate()throws Exception{}}
 int starts,broadStops,ownedStops,ownedRequests;String entryMode="",execution="local",selectedExecution="local",requestedCleanup="";boolean direct,busy,holdCleanup;AndroidNodeStore.Node entry;AndroidStandardExitStore.Entry external,ordinaryEntry;Callback pending,cleanup;
 static final class RestorePoint{final AndroidHomeStateStore.Snapshot home;final String topology="off";RestorePoint(AndroidHomeStateStore.Snapshot s){home=s;}boolean connected(){return home.connected;}}
 RestorePoint captureRestorePoint(){if(isActiveOrTransitioning())throw new IllegalStateException("fixture has no captured live graph");return new RestorePoint(AndroidHomeStateStore.value);}
 boolean restorePointCurrent(RestorePoint p){return idleCurrent(p.home);}
 boolean idleCurrent(AndroidHomeStateStore.Snapshot idle){return !busy&&!AndroidHomeStateStore.value.connected&&idle.sessionId.equals(AndroidHomeStateStore.value.sessionId)&&idle.pathGeneration==AndroidHomeStateStore.value.pathGeneration;}
 AndroidHomeStateStore.Snapshot captureIdle(){if(busy||AndroidHomeStateStore.value.connected)throw new IllegalStateException("native owner retained");return AndroidHomeStateStore.value;}
 boolean restoredCurrent(RestorePoint point,String session){return false;}void restoreCaptured(RestorePoint p,AndroidHomeStateStore.Snapshot idle,Callback cb){throw new AssertionError("unexpected restore of off fixture");}
 boolean cancelPending(Callback cb){if(cb!=pending)return false;pending=null;cb.finished(false,"permission cancelled");return true;}
 void stopCaptured(String session,String topology,Callback cb){disconnectExternal(session,cb);}
 boolean isActiveOrTransitioning(){return busy||AndroidHomeStateStore.value.connected;}
 void connectExternal(AndroidNodeStore.Node node,AndroidStandardExitStore.Entry exit,boolean d,String mode,String execution,Callback cb){starts++;entry=node;ordinaryEntry=null;external=exit;direct=d;entryMode=mode;this.execution=execution;selectedExecution=execution.equals("auto")?"server":execution;pending=cb;}
 void connectOrdinaryTor(AndroidStandardExitStore.Entry node,AndroidStandardExitStore.Entry exit,String execution,Callback cb){starts++;entry=null;ordinaryEntry=AndroidStandardExitStore.copy(node);external=AndroidStandardExitStore.copy(exit);direct=false;entryMode=AndroidExternalPolicy.protocol(node.protocol);this.execution=execution;selectedExecution=execution;pending=cb;}
 boolean capturedOrdinaryEntryMatches(AndroidHomeStateStore.Snapshot owner,AndroidStandardExitStore.Entry expected){return expected==null?ordinaryEntry==null:ordinaryEntry!=null&&AndroidStandardExitStore.snapshot(expected).equals(AndroidStandardExitStore.snapshot(ordinaryEntry));}
 String capturedExternalExecution(AndroidHomeStateStore.Snapshot owner,String requested){if(!owner.sessionId.equals(AndroidHomeStateStore.value.sessionId)||!requested.equals(execution))throw new IllegalStateException("stale execution receipt");return selectedExecution;}
 void connectNode(AndroidNodeStore.Node n,String mode,List<String> layers,Callback cb){starts++;pending=cb;}
 void connectMultihop(AndroidNodeStore.Node a,AndroidNodeStore.Node b,String mode,String execution,String entry,Callback cb){starts++;pending=cb;}
 void disconnect(Callback cb){broadStops++;AndroidHomeStateStore.value=new AndroidHomeStateStore.Snapshot();cb.finished(true,"broad native stop");}
 void disconnectExternal(String session,Callback cb){ownedRequests++;requestedCleanup=session;cleanup=cb;if(holdCleanup)return;completeCleanup();}
 void completeCleanup(){boolean owned=!requestedCleanup.isEmpty()&&requestedCleanup.equals(AndroidHomeStateStore.value.sessionId);if(owned){ownedStops++;long g=AndroidHomeStateStore.value.pathGeneration;AndroidHomeStateStore.value=new AndroidHomeStateStore.Snapshot();AndroidHomeStateStore.value.pathGeneration=g+2;}cleanup.finished(owned,"captured external stop");}
 void prove(String id){try{pending.validate();}catch(Exception stale){pending.finished(false,stale.toString());return;}AndroidHomeStateStore.Snapshot s=new AndroidHomeStateStore.Snapshot();s.connected=true;s.sessionId=id;s.phase="connected";s.pathProof="passed";s.logicalMode="external";s.activeExternalId=external.id;s.activeExternalProtocol=external.protocol;s.activeEntryId=direct?"":ordinaryEntry!=null?ordinaryEntry.id:entry.id;s.activeEntryMode=direct?"external":entryMode;AndroidHomeStateStore.value=s;pending.owned(id);pending.finished(true,"proved");}
}
final class AndroidSpeedLab{
 interface Callback{void finished(Result result,Throwable error);}static final class Result{}
 // PRODUCTION_DURATION_POLICY
 static double round(double n){return n;}
 static Callback pending;static int starts;static String timing;static double min,max;
 AndroidSpeedLab(Activity a){}void cancel(){if(pending!=null)pending.finished(null,new IllegalStateException("cancelled"));}void run(String mode,double low,double high,Callback cb){starts++;timing=mode;min=low;max=high;pending=cb;}
}
final class AndroidNativeHopMeasurement{
 interface Callback{void progress(String status);void finished(String status,Throwable error);}
 void cancel(){}
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
  Fixture(Path root)throws Exception{check(!AndroidMTUMeasurementGate.held(),"previous transaction leaked its MTU hold");AndroidHomeStateStore.value=new AndroidHomeStateStore.Snapshot();AndroidSpeedLab.starts=0;AndroidSpeedLab.pending=null;LayeredVpnService.calls=0;LayeredVpnService.quiesce=null;AndroidStandardExitStore.saved.clear();file=Files.createTempFile(root,"speed-entry-",".json");Files.writeString(file,"captured full entry");request.scope="temporary";request.topology="external";request.externalDirect=false;request.entry=new AndroidNodeStore.Node("entry",file.toFile());request.entryMode="max-quic-awg";request.standardExit=new AndroidStandardExitStore.Entry();request.durationMode="custom";request.minSeconds=2;request.maxSeconds=3;}
  void run(){controller.run(request,result);}void drain(){LayeredVpnService.quiesce.accept(null);}void finish(){AndroidSpeedLab.pending.finished(new AndroidSpeedLab.Result(),null);}
 }
 static void allEntries(Path root)throws Exception{
  for(String protocol:new String[]{"wireguard","amneziawg","socks5","http","https","shadowsocks","hysteria2","openvpn","tor","tor-bridge"})for(String mode:ALL)for(String execution:protocol.startsWith("tor")?new String[]{"local"}:new String[]{"local","server","auto"}){
   Fixture f=new Fixture(root);f.request.entryMode=mode;f.request.standardExit.protocol=protocol;f.request.execution=execution;String secret=f.request.standardExit.secret;f.run();check(f.connection.starts==0&&AndroidMTUMeasurementGate.held(),"temporary graph started before MTU drain");
   f.request.entryMode="wg";f.request.execution="changed";f.request.standardExit.secret="changed-caller-key";f.request.standardExit.protocol="http";f.request.minSeconds=7;f.request.topology="system-direct";f.drain();
   check(f.connection.starts==1&&f.connection.entryMode.equals(mode)&&f.connection.external.protocol.equals(protocol)&&f.connection.external.secret.equals(secret)&&f.connection.execution.equals(execution),"Speed Lab dropped captured external credentials, execution or selected entry");
   f.connection.prove("test-owned");check(AndroidSpeedLab.starts==1&&AndroidSpeedLab.min==2&&AndroidSpeedLab.max==3,"measurement did not use captured timing and proven path");f.finish();
   check(f.result.completions==1&&f.result.error==null&&!f.controller.isRunning()&&!AndroidMTUMeasurementGate.held(),"test transaction did not finish cleanly");check(f.connection.broadStops==0&&f.connection.ownedStops==1&&f.connection.requestedCleanup.equals("test-owned"),"temporary external cleanup escaped its exact Home owner");
  }
  for(String reason:new String[]{"invalid","empty","direct","tor"}){Fixture bad=new Fixture(root);bad.request.execution=reason.equals("empty")?"":reason.equals("invalid")?"invalid":"server";if(reason.equals("direct"))bad.request.externalDirect=true;if(reason.equals("tor"))bad.request.standardExit.protocol="tor";bad.run();check(bad.result.error!=null&&bad.connection.starts==0&&LayeredVpnService.calls==0&&!AndroidMTUMeasurementGate.held(),"Invalid external execution suspended the original path: "+reason);}
  for(boolean requested:new boolean[]{false,true}){Fixture changed=new Fixture(root);changed.request.execution="auto";changed.run();changed.drain();changed.connection.prove("compare-owned");if(requested)changed.connection.execution="local";else changed.connection.selectedExecution="local";changed.finish();check(changed.result.error!=null&&changed.result.result==null,"Changed external execution kept a speed score");}
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
 static void ordinary(Fixture f,String protocol,String tor){
  f.request.entry=null;f.request.ordinaryEntry=new AndroidStandardExitStore.Entry();f.request.ordinaryEntry.id="entry";f.request.ordinaryEntry.protocol=protocol;f.request.ordinaryEntry.secret="independent ordinary private source";f.request.ordinaryEntry.policy="ordinary selected DNS";f.request.standardExit.protocol=tor;f.request.standardExit.policy="Tor selected DNS";f.request.entryMode=AndroidExternalPolicy.protocol(protocol);f.request.execution="local";
  AndroidStandardExitStore.saved.put(f.request.ordinaryEntry.id,AndroidStandardExitStore.copy(f.request.ordinaryEntry));AndroidStandardExitStore.saved.put(f.request.standardExit.id,AndroidStandardExitStore.copy(f.request.standardExit));
 }
 static void ordinaryPaths(Path root)throws Exception{
  for(String protocol:List.of("wireguard","amneziawg","socks5","http","https","shadowsocks","hysteria2","openvpn"))for(String tor:List.of("tor","tor-bridge")){
   Fixture f=new Fixture(root);ordinary(f,protocol,tor);String entry=AndroidStandardExitStore.snapshot(f.request.ordinaryEntry),exit=AndroidStandardExitStore.snapshot(f.request.standardExit);f.run();check(f.connection.starts==0&&AndroidMTUMeasurementGate.held(),"ordinary temporary path started before MTU drain");
   f.request.ordinaryEntry.secret="mutated caller ordinary key";f.request.ordinaryEntry.policy="mutated caller ordinary DNS";f.request.standardExit.secret="mutated caller Tor source";f.request.entryMode="wg";f.request.execution="server";f.drain();
   check(f.connection.starts==1&&f.connection.entry==null&&f.connection.ordinaryEntry!=null&&entry.equals(AndroidStandardExitStore.snapshot(f.connection.ordinaryEntry))&&exit.equals(AndroidStandardExitStore.snapshot(f.connection.external))&&f.connection.entryMode.equals(AndroidExternalPolicy.protocol(protocol))&&f.connection.execution.equals("local"),"ordinary test dropped frozen kind, source, execution or canonical mode");
   f.connection.prove("ordinary-test");check(AndroidSpeedLab.starts==1,"proved ordinary path never measured");f.finish();check(f.result.completions==1&&f.result.error==null&&f.result.result!=null&&f.connection.ownedStops==1&&f.connection.broadStops==0&&!AndroidMTUMeasurementGate.held(),"ordinary test retained a live owner or lost its valid result");
  }
  for(String invalid:List.of("dual-kind","direct","same-id","wrong-mode","server","auto","tor-entry","ordinary-exit","wrong-scope","entry-removed","exit-removed","entry-key","exit-key")){
   Fixture f=new Fixture(root);ordinary(f,"socks5","tor-bridge");if(invalid.equals("dual-kind"))f.request.entry=new AndroidNodeStore.Node("entry",f.file.toFile());if(invalid.equals("direct"))f.request.externalDirect=true;if(invalid.equals("same-id"))f.request.ordinaryEntry.id=f.request.standardExit.id;if(invalid.equals("wrong-mode"))f.request.entryMode="http-connect";if(invalid.equals("server")||invalid.equals("auto"))f.request.execution=invalid;if(invalid.equals("tor-entry"))f.request.ordinaryEntry.protocol="tor";if(invalid.equals("ordinary-exit"))f.request.standardExit.protocol="socks5";if(invalid.equals("wrong-scope"))f.request.scope="current";
   if(invalid.equals("entry-removed"))AndroidStandardExitStore.saved.remove("entry");if(invalid.equals("exit-removed"))AndroidStandardExitStore.saved.remove("exit");if(invalid.equals("entry-key"))AndroidStandardExitStore.saved.get("entry").secret="changed";if(invalid.equals("exit-key"))AndroidStandardExitStore.saved.get("exit").secret="changed";
   f.run();check(f.result.error!=null&&f.connection.starts==0&&LayeredVpnService.calls==0&&!AndroidMTUMeasurementGate.held(),"invalid ordinary request suspended a path: "+invalid);
  }
 }
 static void ordinaryStale(Path root)throws Exception{
  for(String stage:List.of("quiesce","permission","http"))for(String source:List.of("entry-key","entry-policy","entry-removed","exit-key","exit-policy","exit-removed")){
   Fixture f=new Fixture(root);ordinary(f,"https","tor-bridge");f.run();if(!stage.equals("quiesce"))f.drain();if(stage.equals("http"))f.connection.prove("owned-ordinary");String id=source.startsWith("entry")?"entry":"exit";
   if(source.endsWith("removed"))AndroidStandardExitStore.saved.remove(id);else if(source.endsWith("policy"))AndroidStandardExitStore.saved.get(id).policy="replaced selected DNS";else AndroidStandardExitStore.saved.get(id).secret="replaced private source";
   if(stage.equals("quiesce"))f.drain();else if(stage.equals("permission"))f.connection.prove("stale-permission");else f.finish();
   check(f.result.completions==1&&f.result.error!=null&&f.result.result==null&&!AndroidMTUMeasurementGate.held(),"changed ordinary source kept a score or lease: "+stage+"/"+source);check(f.connection.broadStops==0&&f.connection.ownedStops==(stage.equals("http")?1:0),"stale ordinary source cleanup escaped its captured owner");
  }
  for(String replacement:List.of("key","kind")){
   Fixture f=new Fixture(root);ordinary(f,"socks5","tor");f.run();f.drain();f.connection.prove("retained-home");if(replacement.equals("kind"))f.connection.ordinaryEntry=null;else f.connection.ordinaryEntry.secret="different runtime owner";f.finish();
   check(f.result.error!=null&&f.result.result==null&&f.connection.ownedStops==1,"ordinary runtime substitution kept a temporary result: "+replacement);
  }
 }
 public static void main(String[]args)throws Exception{Path root=Path.of(args[0]);allEntries(root);staleAndDenied(root);callbacks(root);ordinaryPaths(root);ordinaryStale(root);System.out.println("Android external Speed Lab: "+checks+" checks; all19 Router modes,8 ordinary modes, frozen sources, stale permission/runtime and captured cleanup");}
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
    assert 'q.entryMode="external".equals(q.topology)&&q.externalDirect?"":selectedEntryMode()' in dialog
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
            ("request.externalDirect,request.entryMode,request.execution,bridge", 'request.externalDirect,"wg",request.execution,bridge', "exact selected entry"),
            ("request.externalDirect,request.entryMode,request.execution,bridge", 'request.externalDirect,request.entryMode,"local",bridge', "captured execution"),
            ("AndroidStandardExitStore.copy(input.standardExit)", "input.standardExit", "frozen external credentials"),
            ("AndroidStandardExitStore.copy(input.ordinaryEntry)", "input.ordinaryEntry", "frozen ordinary credentials"),
            ("if(request.ordinaryEntry==null)return;", "if(true)return;", "ordinary saved source ownership"),
            ("if(!connection.capturedOrdinaryEntryMatches(state,q.ordinaryEntry))return false;", "", "ordinary runtime ownership"),
            ("connection.stopCaptured(home,topology,new AndroidUnifiedConnectionController.Callback()", "connection.disconnect(new AndroidUnifiedConnectionController.Callback()", "captured external cleanup"),
        ):
            assert original.count(old) == 1, label
            path.write_text(original.replace(old, new))
            subprocess.run(compile_args, check=True, timeout=45)
            result = subprocess.run(run_args, capture_output=True, text=True, timeout=25)
            assert result.returncode != 0 and "AssertionError" in result.stderr, label + " negative control escaped"
            path.write_text(original)
        print("Android external Speed Lab negative controls: 7 rejected")


if __name__ == "__main__":
    main()
