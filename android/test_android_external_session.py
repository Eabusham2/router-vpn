#!/usr/bin/env python3
"""Execute native-proof ownership and the full shipping service close boundary.

Only Android and native handles are doubled. The production binder, service,
numeric parser and deterministic concurrent cancellation paths are executed.
"""
from pathlib import Path
import importlib.util
import os
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
JAVA = ROOT / "android/app/src/main/java/com/eabusham/routervpn"
spec = importlib.util.spec_from_file_location("external_service_boundaries", ROOT / "android/test_android_tor_session.py")
T = importlib.util.module_from_spec(spec)
spec.loader.exec_module(T)
SOURCES = dict(T.SOURCES)
SOURCES.pop("com/eabusham/routervpn/AndroidExternalSession.java")
SOURCES["io/nekohasekai/libbox/RouterExternalProofRequest.java"] = r'''package io.nekohasekai.libbox;
import org.json.*;import java.util.concurrent.*;import java.util.concurrent.atomic.*;
public class RouterExternalProofRequest {
 public final CommandServer server;public final String source,capture,session;
 public final AtomicInteger cancels=new AtomicInteger();public volatile boolean alive=true,ran,ignoreCancellation;
 public volatile String response;public volatile CountDownLatch entered,release;
 public RouterExternalProofRequest(CommandServer s,String a,String b,String id){server=s;source=a;capture=b;session=id;}
 public JSONObject valid()throws Exception {boolean entry=!capture.equals("{}");return new JSONObject().put("schema",1).put("session_id",session).put("source_sha256","a".repeat(64)).put("config_sha256","b".repeat(64)).put("exit_id","exit-owned").put("entry_id",entry?"entry-owned":"").put("entry_node_id",entry?"c".repeat(64):"").put("ip","8.8.4.4").put("dns_proven",true).put("entry_proven",entry).put("checked_at",System.currentTimeMillis());}
 public String run()throws Exception {if(entered!=null){entered.countDown();release.await();}ran=true;if(!alive&&!ignoreCancellation)throw new IllegalStateException("cancelled");return response==null?valid().toString():response;}
 public void cancel(){cancels.incrementAndGet();if(!ignoreCancellation){alive=false;if(release!=null)release.countDown();}}
 public boolean healthy(){return alive&&ran;}
}'''
SOURCES["io/nekohasekai/libbox/Libbox.java"] = SOURCES["io/nekohasekai/libbox/Libbox.java"][:-1] + r'''
 public static volatile RouterExternalProofRequest externalNext,externalCreated;
 public static volatile java.util.concurrent.CountDownLatch externalFactoryEntered,externalFactoryRelease;
 public static RouterExternalProofRequest routerExternalCreateProof(CommandServer s,String source,String capture,String id)throws Exception{
  RouterExternalProofRequest r=externalNext==null?new RouterExternalProofRequest(s,source,capture,id):externalNext;externalCreated=r;
  if(externalFactoryEntered!=null){externalFactoryEntered.countDown();externalFactoryRelease.await();}return r;
 }
 public static void externalReset(){reset();externalNext=null;externalCreated=null;externalFactoryEntered=null;externalFactoryRelease=null;}
}'''

HARNESS = r'''package com.eabusham.routervpn;
import org.json.*;import io.nekohasekai.libbox.*;import java.util.concurrent.*;import java.util.concurrent.atomic.*;import java.lang.reflect.*;import java.nio.file.*;
public class ExternalSessionTest {
 static int checks;interface Attempt{void run()throws Exception;}static void check(boolean ok,String msg){checks++;if(!ok)throw new AssertionError(msg);}static void reject(Attempt a)throws Exception{checks++;try{a.run();}catch(Exception expected){return;}throw new AssertionError("unowned external proof accepted");}
 static void waitFor(CountDownLatch latch)throws Exception{check(latch.await(2,TimeUnit.SECONDS),"proof boundary not reached");}
 static class Fixture implements AndroidExternalSession.Owner {
  CommandServer server=new CommandServer(null,null);volatile CommandServer currentServer=server;volatile String network="wifi-1";volatile AndroidExternalSession session;final boolean entry;
  Fixture(boolean entry)throws Exception{this.entry=entry;JSONObject p=new JSONObject().put("source_sha256","a".repeat(64)).put("config_sha256","b".repeat(64)).put("expected_public_ip","8.8.4.4").put("exit_id","exit-owned");if(entry)p.put("entry_id","entry-owned").put("entry_node_id","c".repeat(64));JSONObject capture=new JSONObject();if(entry)capture.put("entry",new JSONObject().put("id","entry-owned"));
   session=new AndroidExternalSession(new JSONObject().put("session_id","session-owned").put("external_id","exit-owned").put("source_config","exact-source").put("capture_json",capture.toString()).put("metadata_json",p.toString()),server,this);}
  public boolean current(AndroidExternalSession s,CommandServer c){return s==session&&c==currentServer;}public String network(){return network;}
  RouterExternalProofRequest request(){RouterExternalProofRequest r=new RouterExternalProofRequest(server,"exact-source",entry?"{\"entry\":{\"id\":\"entry-owned\"}}":"{}","session-owned");Libbox.externalNext=r;return r;}
 }
 static class Job {final AtomicReference<Throwable> error=new AtomicReference<>();final Thread thread;Job(Fixture f){thread=new Thread(()->{try{f.session.prove();}catch(Throwable t){error.set(t);}},"external-proof-test");thread.start();}void finish(boolean failed)throws Exception{thread.join(2000);check(!thread.isAlive(),"proof escaped bounded join");check((error.get()!=null)==failed,"stale proof became successful");}}
 static void success()throws Exception{
  for(boolean entry:new boolean[]{false,true}){Libbox.externalReset();Fixture f=new Fixture(entry);check(!f.session.healthy(),"unproved owner healthy");reject(()->f.session.result("session-owned","exit-owned"));f.session.prove();check(f.session.healthy(),"valid proof not adopted");
   check(Libbox.externalCreated.server==f.server&&Libbox.externalCreated.source.equals("exact-source"),"proof used another graph/server");check(new JSONObject(Libbox.externalCreated.capture).has("entry")==entry,"entry capture dropped");
   check(new JSONObject(f.session.result("session-owned","exit-owned")).getBoolean("dns_proven"),"DNS not required");reject(()->f.session.result("other","exit-owned"));reject(()->f.session.result("session-owned","other"));reject(f.session::prove);
   Libbox.externalCreated.alive=false;check(!f.session.healthy(),"native replacement kept result");}
 }
 static void rejection()throws Exception{
  for(String field:new String[]{"schema","session_id","source_sha256","config_sha256","exit_id","entry_id","entry_node_id","ip","dns_proven","entry_proven","checked_at","future","extra","missing","typed","hostname","legacy","mapped","oversized"}){
   Libbox.externalReset();Fixture f=new Fixture(true);RouterExternalProofRequest r=f.request();JSONObject p=r.valid();
   switch(field){case "schema":p.put(field,2);break;case "dns_proven":case "entry_proven":p.put(field,false);break;case "checked_at":p.put(field,System.currentTimeMillis()-60000);break;case "future":p.put("checked_at",System.currentTimeMillis()+120000);break;case "extra":p.put("foreign",true);break;case "missing":p.remove("entry_id");break;case "typed":p.put("dns_proven","true");break;case "hostname":p.put("ip","must-not-resolve.example");break;case "legacy":p.put("ip","010.1.2.3");break;case "mapped":p.put("ip","::ffff:8.8.4.4");break;case "oversized":p.put("ip","x".repeat(9000));break;case "ip":p.put(field,"8.8.8.8");break;default:p.put(field,"different-owner");}
   r.response=p.toString();reject(f.session::prove);check(!f.session.healthy(),"invalid proof healthy: "+field);
  }
  Libbox.externalReset();Fixture direct=new Fixture(false);RouterExternalProofRequest r=direct.request();r.response=r.valid().put("entry_proven",true).toString();reject(direct.session::prove);
 }
 static void cancellation()throws Exception{
  Libbox.externalReset();Fixture never=new Fixture(false);never.session.cancel();reject(never.session::prove);check(Libbox.externalCreated==null,"cancelled owner created request");
  for(String change:new String[]{"cancel","late-cancel","network","server","native","session"}){
   Libbox.externalReset();Fixture f=new Fixture(true);AndroidExternalSession owned=f.session;RouterExternalProofRequest r=f.request();r.entered=new CountDownLatch(1);r.release=new CountDownLatch(1);r.ignoreCancellation=!change.equals("cancel");Job job=new Job(f);waitFor(r.entered);
   if(change.contains("cancel")){long began=System.nanoTime();owned.cancel();check(System.nanoTime()-began<250000000L,"Cancel waited for proof worker");check(r.cancels.get()==1,"Cancel lost native request");}
   if(change.equals("network"))f.network="cellular-2";if(change.equals("server"))f.currentServer=new CommandServer(null,null);if(change.equals("native"))r.alive=false;if(change.equals("session"))f.session=new Fixture(false).session;
   r.release.countDown();job.finish(true);check(!owned.healthy(),"late proof adopted into "+change+" owner");
  }
  Libbox.externalReset();Fixture factory=new Fixture(false);Libbox.externalFactoryEntered=new CountDownLatch(1);Libbox.externalFactoryRelease=new CountDownLatch(1);Job job=new Job(factory);waitFor(Libbox.externalFactoryEntered);RouterExternalProofRequest request=Libbox.externalCreated;factory.session.cancel();factory.currentServer=new CommandServer(null,null);Libbox.externalFactoryRelease.countDown();job.finish(true);check(request.cancels.get()==1&&!request.ran,"late factory escaped cancellation");
 }
 static Field field(String name)throws Exception{Field f=LayeredVpnService.class.getDeclaredField(name);f.setAccessible(true);return f;}static void close(LayeredVpnService s)throws Exception{Method m=LayeredVpnService.class.getDeclaredMethod("closeCoreLocked");m.setAccessible(true);try{m.invoke(s);}catch(InvocationTargetException e){throw (Exception)e.getCause();}}
 static void serviceOwner()throws Exception{
  Libbox.externalReset();LayeredVpnService s=new LayeredVpnService();CommandServer server=new CommandServer(s,s);android.os.ParcelFileDescriptor tun=new android.os.ParcelFileDescriptor();Path folder=Files.createTempDirectory("external-owned-java-");Files.writeString(folder.resolve("private-capture"),"retained");
  field("externalOwner").setBoolean(s,true);field("commandServer").set(s,server);field("tunDescriptor").set(s,tun);field("activeSession").set(s,folder.toFile());field("activeMode").set(s,"standard-direct-socks5");
  Libbox.failClose=true;reject(()->close(s));check(field("commandServer").get(s)==server&&field("externalOwner").getBoolean(s),"unconfirmed close forgot native owner");check(!tun.closed&&Files.exists(folder.resolve("private-capture")),"unconfirmed close released TUN/private capture");check(server.uncheckedCloses==0&&server.closes==0,"unchecked close bypassed native drain");
  Libbox.failClose=false;close(s);check(field("commandServer").get(s)==null&&!field("externalOwner").getBoolean(s)&&tun.closed&&server.closes==1,"confirmed drain did not release exact owner");s.onDestroy();check(!Files.exists(folder),"closed private session retained");
  LayeredVpnService p=new LayeredVpnService();android.net.Network physical=new android.net.Network();android.net.ConnectivityManager.networks=new android.net.Network[]{physical};field("connectivity").set(p,new android.net.ConnectivityManager());field("externalPhysicalNetwork").set(p,physical);field("externalOwner").setBoolean(p,true);Method identity=LayeredVpnService.class.getDeclaredMethod("executionNetworkIdentity");identity.setAccessible(true);field("executionNetwork").set(p,identity.invoke(p));
  p.autoDetectInterfaceControl(100);check(physical.fdBinds==1&&android.os.ParcelFileDescriptor.duplicate.closed,"external native FD escaped physical owner");p.protectRelaySocket(new java.net.Socket());p.protectRelaySocket((java.net.DatagramSocket)null);check(physical.tcpBinds==1&&physical.udpBinds==1,"relay sockets escaped physical owner");
  android.net.ConnectivityManager.networks=new android.net.Network[]{new android.net.Network()};reject(()->p.autoDetectInterfaceControl(101));check(physical.fdBinds==1,"changed network opened new traffic");p.onDestroy();
 }
 public static void main(String[]args)throws Exception{success();rejection();cancellation();serviceOwner();System.out.println("Android external proof/service lifecycle: "+checks+" executable checks passed");}
}'''


def main():
    jar = Path(os.environ.get("ANDROID_JSON_JAR", "/usr/share/java/com.android.json.jar"))
    if not jar.is_file() or not shutil.which("javac"):
        raise RuntimeError("JDK and Android JSON are required for external owner tests")
    with tempfile.TemporaryDirectory(prefix="routervpn-external-owner-") as directory:
        temp = Path(directory)
        for name, source in SOURCES.items():
            target = temp / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(source)
        app = temp / "com/eabusham/routervpn"
        for name in ("AndroidExternalSession", "AndroidTorSession", "AndroidNumericAddress", "LayeredVpnService"):
            shutil.copyfile(JAVA / (name + ".java"), app / (name + ".java"))
        (app / "ExternalSessionTest.java").write_text(HARNESS)
        compile_args = ["javac", "--release", "17", "-encoding", "UTF-8", "-proc:none", "-cp", str(jar), "-d", str(temp / "classes"), *map(str, temp.rglob("*.java"))]
        run_args = ["java", "-cp", os.pathsep.join((str(temp / "classes"), str(jar))), "com.eabusham.routervpn.ExternalSessionTest"]
        subprocess.run(compile_args, check=True, timeout=45)
        subprocess.run(run_args, check=True, timeout=20)
        mutations = [
            ("AndroidExternalSession.java", "if (cancelled || !current() || !captured.healthy()) throw unavailable();", "", "final proof ownership"),
            ("LayeredVpnService.java", "Libbox.routerStrategyCloseService(commandServer);", "commandServer.closeService();", "checked native drain"),
            ("LayeredVpnService.java", "capturedExternal.bindSocket(borrowed.getFileDescriptor());", "", "physical network binding"),
        ]
        for name, old, new, label in mutations:
            target = app / name
            original = target.read_text()
            if original.count(old) != 1:
                raise AssertionError(f"Missing unique mutation boundary: {label}")
            target.write_text(original.replace(old, new))
            subprocess.run(compile_args, check=True, timeout=45)
            result = subprocess.run(run_args, capture_output=True, text=True, timeout=20)
            if result.returncode == 0:
                raise AssertionError(f"Regression escaped: {label}")
            target.write_text(original)
        print("Android external owner negative controls: 3 rejected")


if __name__ == "__main__":
    main()
