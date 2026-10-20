#!/usr/bin/env python3
"""Execute retained external/Tor proof-to-measurement and native service adoption.

Shipping session and VpnService classes run unchanged. Only Android and native
handles are doubled; encrypted traffic has the separate pinned native gate.
"""
from pathlib import Path
import importlib.util
import os
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
JAVA = ROOT / "android/app/src/main/java/com/eabusham/routervpn"
spec = importlib.util.spec_from_file_location("external_hop_handles", ROOT / "android/test_android_external_session.py")
T = importlib.util.module_from_spec(spec)
spec.loader.exec_module(T)
SOURCES = dict(T.SOURCES)
SOURCES["io/nekohasekai/libbox/RouterHopMeasurement.java"] = r'''package io.nekohasekai.libbox;
public class RouterHopMeasurement {
 public int closes,invalidations,starts,cancels;public String request="";
 public void close(){closes++;}public void networkChanged(){invalidations++;}
 public void start(String id,long bytes){if(bytes!=8388608)throw new AssertionError("unbounded request");starts++;request=id;}
 public void cancel(String id){if(!id.equals(request))throw new AssertionError("cancel lost request");cancels++;}
 public String statusJSON(){return "{\"request_id\":\""+request+"\",\"complete\":false}";}
}'''
native = SOURCES["io/nekohasekai/libbox/Libbox.java"]
native = native.replace(
    "public static RouterHopMeasurement routerTorCreateHopMeasurement(CommandServer s,RouterTorProofRequest proof,String id)throws Exception{return new RouterHopMeasurement();}",
    "public static RouterHopMeasurement routerTorCreateHopMeasurement(CommandServer s,RouterTorProofRequest proof,String id)throws Exception{return makeMeasurement(s,proof,\"\",\"\",id);}",
).replace(
    "public static RouterHopMeasurement routerExternalCreateHopMeasurement(CommandServer s,RouterExternalProofRequest proof,String source,String capture,String id)throws Exception{return new RouterHopMeasurement();}",
    "public static RouterHopMeasurement routerExternalCreateHopMeasurement(CommandServer s,RouterExternalProofRequest proof,String source,String capture,String id)throws Exception{return makeMeasurement(s,proof,source,capture,id);}",
)
SOURCES["io/nekohasekai/libbox/Libbox.java"] = native[:-1] + r'''
 public static volatile CommandServer measurementServer;public static volatile Object measurementProof;
 public static volatile String measurementSource,measurementCapture,measurementID;
 public static volatile RouterHopMeasurement measurementCreated;public static int measurementCalls;
 public static volatile boolean measurementNull;public static volatile java.util.concurrent.CountDownLatch measurementEntered,measurementRelease;
 public static void measurementReset(){externalReset();measurementServer=null;measurementProof=null;measurementSource="";measurementCapture="";measurementID="";measurementCreated=null;measurementCalls=0;measurementNull=false;measurementEntered=null;measurementRelease=null;}
 private static RouterHopMeasurement makeMeasurement(CommandServer s,Object p,String source,String capture,String id)throws Exception{
  measurementCalls++;measurementServer=s;measurementProof=p;measurementSource=source;measurementCapture=capture;measurementID=id;
  RouterHopMeasurement m=measurementNull?null:new RouterHopMeasurement();measurementCreated=m;
  if(measurementEntered!=null){measurementEntered.countDown();measurementRelease.await();}return m;
 }
}'''

HARNESS = r'''package com.eabusham.routervpn;
import org.json.*;import io.nekohasekai.libbox.*;import java.lang.reflect.*;import java.util.concurrent.*;import java.util.concurrent.atomic.*;
public class ExternalHopMeasurementTest {
 static int checks;interface Attempt{void run()throws Exception;}
 static void check(boolean ok,String why){checks++;if(!ok)throw new AssertionError(why);}
 static void reject(Attempt run)throws Exception{checks++;try{run.run();}catch(Exception expected){return;}throw new AssertionError("unowned measurement accepted");}
 static final class Fixture implements AndroidExternalSession.Owner,AndroidTorSession.Owner {
  final CommandServer server=new CommandServer(null,null);volatile CommandServer currentServer=server;volatile String network="wifi-1";volatile boolean current=true;
  final AndroidExternalSession external;final AndroidTorSession tor;final String capture;final boolean isTor;
  Fixture(boolean isTor,boolean entry)throws Exception{this.isTor=isTor;JSONObject cap=new JSONObject();if(entry)cap.put("entry",new JSONObject().put("id","entry-owned"));capture=cap.toString();
   JSONObject policy=new JSONObject().put("source_sha256","a".repeat(64)).put("config_sha256","b".repeat(64)).put("exit_id","exit-owned").put("expected_public_ip","8.8.4.4");if(entry)policy.put("entry_id","entry-owned").put("entry_node_id","c".repeat(64));
   external=new AndroidExternalSession(new JSONObject().put("session_id","session-owned").put("external_id","exit-owned").put("source_config","exact-source").put("capture_json",capture).put("metadata_json",policy.toString()),server,this);
   JSONObject metadata=new JSONObject().put("session_id","session-owned").put("external_id","exit-owned");if(entry)metadata.put("predecessor_profile",new JSONObject().put("id","entry-owned"));tor=new AndroidTorSession(metadata,server,this);
  }
  public boolean current(AndroidExternalSession s,CommandServer c){return current&&s==external&&c==currentServer;}
  public boolean current(AndroidTorSession s,CommandServer c){return current&&s==tor&&c==currentServer;}
  public String network(){return network;}
  void prove()throws Exception{if(isTor)tor.prove();else external.prove();}
  RouterHopMeasurement create()throws Exception{return isTor?tor.newHopMeasurement():external.newHopMeasurement();}
  Object proof(){return isTor?Libbox.created:Libbox.externalCreated;}
  void cancel(){if(isTor)tor.cancel();else external.cancel();}
  void change(String reason){if(reason.equals("cancel"))cancel();if(reason.equals("network"))network="cellular-2";if(reason.equals("server"))currentServer=new CommandServer(null,null);if(reason.equals("session"))current=false;if(reason.equals("native")){if(isTor)Libbox.created.alive=false;else Libbox.externalCreated.alive=false;}}
 }
 static void exactAndRejected()throws Exception{
  for(boolean tor:new boolean[]{false,true})for(boolean entry:new boolean[]{false,true}){
   Libbox.measurementReset();Fixture f=new Fixture(tor,entry);reject(f::create);check(Libbox.measurementCalls==0,"measurement created before path proof");f.prove();Object proof=f.proof();RouterHopMeasurement m=f.create();
   check(m==Libbox.measurementCreated&&Libbox.measurementCalls==1,"retained native factory not used");check(Libbox.measurementServer==f.server&&Libbox.measurementProof==proof,"measurement used another Box or an unproved handle");
   if(tor)check(Libbox.measurementID.equals("exit-owned")&&Libbox.measurementSource.isEmpty(),"Tor exit identity was substituted");else check(Libbox.measurementID.equals("session-owned")&&Libbox.measurementSource.equals("exact-source")&&Libbox.measurementCapture.equals(f.capture),"external source or frozen policy changed");
   m.close();check(m.closes==1,"native measurement owner not releasable");
   f.cancel();reject(f::create);check(Libbox.measurementCalls==1,"cancelled proof created another measurement");
  }
  for(boolean tor:new boolean[]{false,true})for(String reason:new String[]{"network","server","session","native"}){Libbox.measurementReset();Fixture f=new Fixture(tor,true);f.prove();f.change(reason);reject(f::create);check(Libbox.measurementCalls==0,"stale proof reached factory: "+reason);}
  for(boolean tor:new boolean[]{false,true}){Libbox.measurementReset();Fixture f=new Fixture(tor,false);f.prove();Libbox.measurementNull=true;reject(f::create);}
 }
 static void lateFactory()throws Exception{
  for(boolean tor:new boolean[]{false,true})for(String reason:new String[]{"cancel","network","server","session","native"}){
   Libbox.measurementReset();Fixture f=new Fixture(tor,true);f.prove();Libbox.measurementEntered=new CountDownLatch(1);Libbox.measurementRelease=new CountDownLatch(1);
   AtomicReference<RouterHopMeasurement> result=new AtomicReference<>();AtomicReference<Throwable> error=new AtomicReference<>();Thread worker=new Thread(()->{try{result.set(f.create());}catch(Throwable failed){error.set(failed);}},"external-measurement-factory");worker.start();
   check(Libbox.measurementEntered.await(2,TimeUnit.SECONDS),"native measurement factory not reached");long began=System.nanoTime();f.change(reason);check(System.nanoTime()-began<250000000L,"cancellation waited for the measurement factory");Libbox.measurementRelease.countDown();worker.join(2000);
   check(!worker.isAlive()&&error.get()!=null&&result.get()==null,"late measurement factory escaped its "+reason+" owner");check(Libbox.measurementCreated.closes==1,"late native measurement handle leaked");
  }
 }
 static Field field(String name)throws Exception{Field f=LayeredVpnService.class.getDeclaredField(name);f.setAccessible(true);return f;}
 static Object invoke(LayeredVpnService s,String name,Class<?>[] types,Object...args)throws Exception{Method m=LayeredVpnService.class.getDeclaredMethod(name,types);m.setAccessible(true);try{return m.invoke(s,args);}catch(InvocationTargetException e){throw (Exception)e.getCause();}}
 static LayeredVpnService service(CommandServer server)throws Exception{
  LayeredVpnService s=new LayeredVpnService();android.net.ConnectivityManager.networks=new android.net.Network[]{new android.net.Network()};field("connectivity").set(s,new android.net.ConnectivityManager());field("commandServer").set(s,server);field("executionNetwork").set(s,invoke(s,"executionNetworkIdentity",new Class<?>[]{}));return s;
 }
 static void adopt(LayeredVpnService s,RouterHopMeasurement m,CommandServer server,long generation)throws Exception{invoke(s,"adoptHopMeasurement",new Class<?>[]{RouterHopMeasurement.class,CommandServer.class,long.class},m,server,generation);}
 static void serviceAdoption()throws Exception{
  for(String reason:new String[]{"valid","stop","generation","server","network","existing","tor-proof","external-proof"}){
   Libbox.measurementReset();CommandServer server=new CommandServer(null,null);LayeredVpnService s=service(server);RouterHopMeasurement captured=new RouterHopMeasurement();RouterHopMeasurement old=new RouterHopMeasurement();
   long generation=0;if(reason.equals("stop"))field("explicitStop").setBoolean(s,true);if(reason.equals("generation"))generation=1;if(reason.equals("server"))field("commandServer").set(s,new CommandServer(null,null));if(reason.equals("network"))field("executionNetwork").set(s,"old-network");if(reason.equals("existing"))field("hopMeasurement").set(s,old);
   if(reason.endsWith("proof")){Fixture f=new Fixture(reason.startsWith("tor"),true);f.prove();f.cancel();field(reason.startsWith("tor")?"torSession":"externalSession").set(s,reason.startsWith("tor")?f.tor:f.external);}
   final long requested=generation;if(reason.equals("valid")){adopt(s,captured,server,requested);check(field("hopMeasurement").get(s)==captured&&captured.closes==0,"owned measurement not adopted");}
   else{reject(()->adopt(s,captured,server,requested));check(captured.closes==1,"rejected native handle not closed");if(reason.equals("existing"))check(field("hopMeasurement").get(s)==old&&old.closes==0,"new factory displaced an existing measurement");}
   s.onDestroy();
  }
  Libbox.measurementReset();CommandServer server=new CommandServer(null,null);LayeredVpnService s=service(server);RouterHopMeasurement m=new RouterHopMeasurement();adopt(s,m,server,0);field("externalOwner").setBoolean(s,true);Libbox.failClose=true;
  reject(()->invoke(s,"closeCoreLocked",new Class<?>[]{}));check(m.invalidations==1&&m.closes==0&&field("hopMeasurement").get(s)==m,"unconfirmed Box drain released active measurement");Libbox.failClose=false;invoke(s,"closeCoreLocked",new Class<?>[]{});check(m.closes==1&&field("hopMeasurement").get(s)==null,"confirmed Box drain retained measurement");s.onDestroy();
 }
 public static void main(String[] args)throws Exception{exactAndRejected();lateFactory();serviceAdoption();System.out.println("Android external/Tor measurement ownership: "+checks+" checks; exact proof, late factories, native adoption and retained teardown");}
}'''


def main():
    jar = Path(os.environ.get("ANDROID_JSON_JAR", "/usr/share/java/com.android.json.jar"))
    if not jar.is_file() or not shutil.which("javac"):
        raise RuntimeError("JDK and Android JSON are required")
    with tempfile.TemporaryDirectory(prefix="routervpn-external-hop-") as directory:
        root = Path(directory)
        for name, source in SOURCES.items():
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(source)
        app = root / "com/eabusham/routervpn"
        for name in ("AndroidExternalSession", "AndroidTorSession", "AndroidNumericAddress", "LayeredVpnService"):
            shutil.copyfile(JAVA / (name + ".java"), app / (name + ".java"))
        (app / "ExternalHopMeasurementTest.java").write_text(HARNESS)
        compile_args = ["javac", "--release", "17", "-encoding", "UTF-8", "-proc:none", "-cp", str(jar), "-d", str(root / "classes"), *map(str, root.rglob("*.java"))]
        run_args = ["java", "-cp", os.pathsep.join((str(root / "classes"), str(jar))), "com.eabusham.routervpn.ExternalHopMeasurementTest"]
        subprocess.run(compile_args, check=True, timeout=45)
        subprocess.run(run_args, check=True, timeout=25)
        for name, old, new, label in (
            ("AndroidExternalSession.java", "owned = request == proof && healthy();", "owned = true;", "external late factory"),
            ("AndroidTorSession.java", "owned = request == proof && healthy();", "owned = true;", "Tor late factory"),
            ("LayeredVpnService.java", "generation == lifecycle.get() && commandServer == server && hopMeasurement == null", "commandServer == server && hopMeasurement == null", "native generation adoption"),
        ):
            path = app / name
            source = path.read_text()
            assert source.count(old) == 1, label
            path.write_text(source.replace(old, new))
            subprocess.run(compile_args, check=True, timeout=45)
            result = subprocess.run(run_args, capture_output=True, text=True, timeout=25)
            assert result.returncode != 0 and "AssertionError" in result.stderr, label + " negative control escaped"
            path.write_text(source)
        print("Android external/Tor measurement negative controls: 3 rejected")


if __name__ == "__main__":
    main()
