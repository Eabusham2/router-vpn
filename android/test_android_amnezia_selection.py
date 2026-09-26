#!/usr/bin/env python3
"""Run the shipping AWG controller against JVM engine/Android boundary doubles.

Validates exact Fast/Strong selection and session ownership, not physical VPN
traffic. The actual Amnezia backend is linked by the separate APK build gate.
"""
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
JAVA = ROOT / "android/app/src/main/java/com/eabusham/routervpn"
STUBS = {
    "android/content/Context.java": "package android.content; public class Context { public Context getApplicationContext(){return this;} }",
    "android/util/Base64.java": "package android.util; public final class Base64 {public static final int DEFAULT=0; public static byte[] decode(String s,int f){return java.util.Base64.getDecoder().decode(s);}}",
    "org/amnezia/awg/backend/Tunnel.java": "package org.amnezia.awg.backend; public interface Tunnel {enum State {DOWN,UP,TOGGLE} String getName(); void onStateChange(State s);}",
    "org/amnezia/awg/config/Config.java": "package org.amnezia.awg.config; public final class Config {public final String value; private Config(String v){value=v;} public static Config parse(java.io.InputStream s)throws Exception{return new Config(new String(s.readAllBytes(),java.nio.charset.StandardCharsets.UTF_8));}}",
    "org/amnezia/awg/backend/GoBackend.java": r"""package org.amnezia.awg.backend;
import android.content.Context; import org.amnezia.awg.config.Config;
public final class GoBackend {
 public static volatile int starts,stops; public static volatile Config last; public static volatile boolean failStop;
 public GoBackend(Context c){} public Tunnel.State setState(Tunnel t,Tunnel.State s,Config c){
  if(s==Tunnel.State.UP){starts++;last=c;}else{stops++;if(failStop)throw new IllegalStateException("injected stop failure");}
  t.onStateChange(s);return s;
 }
 public static void reset(){starts=0;stops=0;last=null;failStop=false;}
}""",
    "org/json/JSONObject.java": r"""package org.json;
import java.util.*; import java.util.concurrent.ConcurrentHashMap;
// Only the JSON parser boundary is doubled. The shipping controller still
// selects, decodes and validates its actual private-bundle profile itself.
public final class JSONObject {
 public static final Map<String,JSONObject> documents=new ConcurrentHashMap<>();
 private Map<String,Object> values=new HashMap<>();
 public JSONObject(){} public JSONObject(String text){JSONObject d=documents.get(text);if(d==null)throw new IllegalArgumentException("unknown fixture document");values=d.values;}
 public JSONObject put(String key,Object value){values.put(key,value);return this;}
 public JSONObject optJSONObject(String key){Object v=values.get(key);return v instanceof JSONObject?(JSONObject)v:null;}
 public String optString(String key,String fallback){Object v=values.get(key);return v instanceof String?(String)v:fallback;}
}""",
    "com/eabusham/routervpn/Boundaries.java": r"""package com.eabusham.routervpn;
import android.content.Context; import java.io.File; import org.json.JSONObject;
final class AndroidUnderlyingNetworkMonitor {
 static volatile Runnable recovery; AndroidUnderlyingNetworkMonitor(Context c){}
 void start(Runnable r){recovery=r;} void stop(){recovery=null;}
}
final class AndroidNativeProfilePolicy {
 static volatile int mtu; static String patchWireGuardLikeConfig(JSONObject r,String config,int m){mtu=m;return config;}
}
final class AndroidKillSwitchPolicy {
 static volatile boolean strict; static boolean strictRequested(File f){return strict;} static String requirementMessage(){return "strict fixture requirement";}
}
final class AndroidPathProbe {static volatile boolean valid=true;static boolean prove(File f,int timeout){return valid;}}
final class AndroidHomeStateStore {
 static final class Snapshot {} static int begins,connections,failures,warnings,disconnects; static String raw="";
 static void reset(){begins=connections=failures=warnings=disconnects=0;raw="";}
 static String nodeIdFromBundleFile(File f){return "fixture-node";}
 static void begin(Context c,String logical,String mode,String base,String node){begins++;raw=mode;}
 static void connected(Context c,String logical,String mode,String base,String entry,String node){connections++;raw=mode;}
 static Snapshot beginPathRevalidation(Context c,String reason){return null;}
 static boolean completePathRevalidation(Context c,Snapshot s){return true;}
 static boolean emergencyDisconnectPending(Context c){return false;}
 static void disconnected(Context c){disconnects++;}
 static void warning(Context c,String s){warnings++;}
 static void failed(Context c,String s){failures++;}
}
""",
}
HARNESS = r"""package com.eabusham.routervpn;
import android.content.Context; import java.io.*; import java.nio.file.*; import java.nio.charset.StandardCharsets;
import java.util.*; import java.util.concurrent.*; import org.json.JSONObject;
import org.amnezia.awg.backend.GoBackend; import org.amnezia.awg.backend.Tunnel.State;
public final class AmneziaSelectionHarness {
 static int checks;
 static void check(boolean b,String message){if(!b)throw new AssertionError(message);checks++;}
 static final class Result implements NativeAmneziaWGController.Callback {
  final CountDownLatch latch=new CountDownLatch(1); volatile State state; volatile Throwable error;
  public void done(State s,String m,Throwable e){state=s;error=e;latch.countDown();}
  void await()throws Exception {check(latch.await(4,TimeUnit.SECONDS),"controller callback timed out");}
 }
 static File bundle(Path folder,String... modes)throws Exception {
  JSONObject profiles=new JSONObject();
  for(String mode:modes)profiles.put(mode,new JSONObject().put("awg.conf",Base64.getEncoder().encodeToString(("actual-decoded-"+mode).getBytes(StandardCharsets.UTF_8))));
  String id=UUID.randomUUID().toString();JSONObject.documents.put(id,new JSONObject().put("profiles",profiles));
  return Files.writeString(folder.resolve(id),id).toFile();
 }
 static void reset(){GoBackend.reset();AndroidHomeStateStore.reset();AndroidPathProbe.valid=true;AndroidKillSwitchPolicy.strict=false;AndroidNativeProfilePolicy.mtu=0;}
 static void stop(NativeAmneziaWGController c)throws Exception {Result r=new Result();c.disconnectManaged(r);r.await();check(r.error==null&&r.state==State.DOWN,"managed teardown did not prove DOWN");c.close();}
 public static void main(String[] args)throws Exception {
  Path dir=Path.of(args[0]);File both=bundle(dir,"awg2-fast","awg2-strong");
  for(String mode:new String[]{"awg2-fast","awg2-strong"}) {
   reset();NativeAmneziaWGController c=new NativeAmneziaWGController(new Context());
   try {Result r=new Result();c.connectManaged(both,mode,r);r.await();
    check(r.error==null&&r.state==State.UP,"selected AWG variant failed");
    check(GoBackend.last.value.equals("actual-decoded-"+mode),"selected AWG variant was replaced");
    check(AndroidNativeProfilePolicy.mtu==(mode.equals("awg2-fast")?1400:1360),"variant's MTU policy changed");
    check(AndroidHomeStateStore.begins==0&&AndroidHomeStateStore.connections==0,"managed child took ownership of logical session");
    Result disconnected=new Result();c.disconnectManaged(disconnected);disconnected.await();
    check(AndroidHomeStateStore.disconnects==0,"managed child cleared logical session");
   }finally{c.close();}
  }
  for(String mode:new String[]{"awg2-fast","awg2-strong"}) {
   reset();NativeAmneziaWGController c=new NativeAmneziaWGController(new Context());
   try {File other=bundle(dir,mode.equals("awg2-fast")?"awg2-strong":"awg2-fast");Result r=new Result();c.connectManaged(other,mode,r);r.await();
    check(r.error!=null&&GoBackend.starts==0,"missing selected variant silently fell back");
    check(r.state==State.DOWN,"missing selected profile did not fail closed");
    check(AndroidHomeStateStore.failures==0,"managed failure overwrote logical session");
   }finally{c.close();}
  }
  for(String invalid:new String[]{"awg2-pq","wg","",null,"AWG2-STRONG"}) {
   reset();NativeAmneziaWGController c=new NativeAmneziaWGController(new Context());
   try {Result r=new Result();c.connectManaged(both,invalid,r);r.await();
    check(r.error!=null&&GoBackend.starts==0&&GoBackend.stops==0,"unknown profile touched engine");
    check(AndroidHomeStateStore.begins==0,"invalid variant touched session");
   }finally{c.close();}
  }
  reset();NativeAmneziaWGController c=new NativeAmneziaWGController(new Context());
  try {Result r=new Result();c.connectManaged(both,r);r.await();check(r.error==null&&GoBackend.last.value.equals("actual-decoded-awg2-fast"),"legacy managed caller changed default");stop(c);}finally{c.close();}
  reset();c=new NativeAmneziaWGController(new Context());
  try {Result r=new Result();c.connect(both,r);r.await();check(r.error==null&&AndroidHomeStateStore.begins==1&&AndroidHomeStateStore.connections==1&&AndroidHomeStateStore.raw.equals("awg2-fast"),"direct call failed exact Home ownership");stop(c);}finally{c.close();}
  reset();c=new NativeAmneziaWGController(new Context());AndroidPathProbe.valid=false;
  try {Result r=new Result();c.connectManaged(both,"awg2-strong",r);r.await();check(r.error!=null&&r.state==State.DOWN&&GoBackend.stops>0,"unproven Strong path survived");check(AndroidHomeStateStore.connections==0,"failed path was reported connected");}finally{c.close();}
  reset();c=new NativeAmneziaWGController(new Context());AndroidKillSwitchPolicy.strict=true;
  try {Result r=new Result();c.connectManaged(both,"awg2-strong",r);r.await();check(r.error!=null&&GoBackend.starts==0,"unsupported strict native backend was silently used");}finally{c.close();}
  System.out.println("Shipping Android Amnezia Fast/Strong selection: PASS ("+checks+" executable checks)");
 }
}
"""

def main():
    javac, java = shutil.which("javac"), shutil.which("java")
    if not javac or not java:
        raise SystemExit("JDK required for executable Amnezia selection tests")
    orchestrator = (JAVA / "AndroidModeOrchestrator.java").read_text()
    for marker in ("startAwg(bundle,c.id)", "awg.connectManaged(bundle,rawProfileID,", "NativeAmneziaWGController.supportedRawProfile(id)&&has(profiles,id,\"awg.conf\")"):
        assert marker in orchestrator, "shipping chooser lost exact AWG variant: " + marker
    with tempfile.TemporaryDirectory(prefix="routervpn-awg-selection-") as tmp:
        folder = Path(tmp)
        files = dict(STUBS)
        files["com/eabusham/routervpn/AmneziaSelectionHarness.java"] = HARNESS
        files["com/eabusham/routervpn/NativeAmneziaWGController.java"] = (JAVA / "NativeAmneziaWGController.java").read_text()
        for name, text in files.items():
            path = folder / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)
        classes = folder / "classes"
        subprocess.run([javac, "-encoding", "UTF-8", "-d", str(classes), *[str(folder / x) for x in files]], check=True, timeout=60)
        bundles = folder / "bundles"
        bundles.mkdir()
        subprocess.run([java, "-cp", str(classes), "com.eabusham.routervpn.AmneziaSelectionHarness", str(bundles)], check=True, timeout=30)

if __name__ == "__main__":
    main()
