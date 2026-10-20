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
SOURCES["io/nekohasekai/libbox/RouterMTU.java"] = "package io.nekohasekai.libbox;public class RouterMTU {}"
SOURCES["io/nekohasekai/libbox/RouterMTUPlatform.java"] = "package io.nekohasekai.libbox;public interface RouterMTUPlatform {}"
SOURCES["com/eabusham/routervpn/AndroidMTUSession.java"] = SOURCES["com/eabusham/routervpn/AndroidMTUSession.java"].replace("public void activateExternal(AndroidExternalSession external){}", "public int externalStarts,closes,closeFailures;public AndroidExternalSession activatedExternal;public void activateExternal(AndroidExternalSession external){externalStarts++;activatedExternal=external;}").replace("public void close()throws Exception{}", 'public void close()throws Exception{closes++;if(closeFailures>0){closeFailures--;throw new IllegalStateException("unfinished MTU native cleanup");}}')
SOURCES["com/eabusham/routervpn/AndroidHomeStateStore.java"] = SOURCES["com/eabusham/routervpn/AndroidHomeStateStore.java"].replace("s!=null&&s==value&&!emergency", "s!=null&&s.sessionId.equals(value.sessionId)&&s.activeExternalId.equals(value.activeExternalId)&&!emergency")
SOURCES["android/content/Context.java"] = SOURCES["android/content/Context.java"].replace("public java.io.File getFilesDir(){return null;}", "public java.io.File files;public java.io.File getFilesDir(){return files;}")
SOURCES["android/content/Context.java"] = SOURCES["android/content/Context.java"].replace("public Object getSystemService(String name){return null;}", "public Object getSystemService(String name){return name.equals(NOTIFICATION_SERVICE)?new android.app.NotificationManager():new android.net.ConnectivityManager();}")
SOURCES["android/net/VpnService.java"] = SOURCES["android/net/VpnService.java"].replace("public boolean isAlwaysOn(){return true;}public boolean isLockdownEnabled(){return true;}", "public static boolean lockdown=true;public boolean isAlwaysOn(){return lockdown;}public boolean isLockdownEnabled(){return lockdown;}")
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
 public static RouterHopMeasurement routerExternalCreateHopMeasurement(CommandServer s,RouterExternalProofRequest proof,String source,String capture,String id)throws Exception{return new RouterHopMeasurement();}
 public static RouterMTU newRouterExternalMTU(CommandServer s,RouterMTUPlatform platform,RouterExternalProofRequest proof,String source,String capture)throws Exception{return new RouterMTU();}
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
 static Object invoke(LayeredVpnService service,String name,Class<?>[] types,Object...args)throws Exception{Method method=LayeredVpnService.class.getDeclaredMethod(name,types);method.setAccessible(true);try{return method.invoke(service,args);}catch(InvocationTargetException e){throw (Exception)e.getCause();}}
 static void drain(LayeredVpnService s)throws Exception{((java.util.concurrent.ExecutorService)field("executor").get(s)).submit(()->{}).get(2,TimeUnit.SECONDS);}
 static AndroidHomeStateStore.Snapshot home(boolean connected){AndroidHomeStateStore.Snapshot h=new AndroidHomeStateStore.Snapshot();h.sessionId="home-owned";h.phase=connected?"connected":"connecting";h.pathProof=connected?"passed":"pending";h.connected=connected;h.activeExternalId="exit-owned";h.activeExternalProtocol="socks5";h.expectedExternalIp="8.8.4.4";AndroidHomeStateStore.value=h;AndroidHomeStateStore.emergency=false;return h;}
 static void homeCapture()throws Exception{
  LayeredVpnService s=new LayeredVpnService();AndroidHomeStateStore.Snapshot h=home(false);JSONObject metadata=new JSONObject().put("external_id","exit-owned").put("protocol","socks5").put("entry_mode","external").put("capture_json",new JSONObject().put("expected_public_ip","8.8.4.4").toString());
  Class<?>[] signature={JSONObject.class,String.class};check(invoke(s,"captureExternalHome",signature,metadata,"home-owned")==h,"service substituted Home launch owner");
  for(String altered:new String[]{"home","exit","protocol","ip","entry","proved","emergency"}){
   h=home(false);JSONObject changed=new JSONObject(metadata.toString());String session="home-owned";
   if(altered.equals("home"))session="new-owner";if(altered.equals("exit"))changed.put("external_id","other");if(altered.equals("protocol"))changed.put("protocol","http");if(altered.equals("ip"))h.expectedExternalIp="8.8.8.8";if(altered.equals("entry"))h.activeEntryId="entry-owned";if(altered.equals("proved"))h.phase="connected";if(altered.equals("emergency"))AndroidHomeStateStore.emergency=true;
   final String selected=session;reject(()->invoke(s,"captureExternalHome",signature,changed,selected));
  }
  AndroidHomeStateStore.emergency=false;s.onDestroy();
 }
 static void failedHome()throws Exception{
  for(boolean replacement:new boolean[]{false,true}){
   Libbox.externalReset();Fixture f=new Fixture(false);f.session.prove();LayeredVpnService s=new LayeredVpnService();s.files=Files.createTempDirectory("external-home-service-").toFile();s.onCreate();
   Path folder=s.files.toPath().resolve("layered-sessions/owned");Files.createDirectories(folder);Files.writeString(folder.resolve("capture"),"private");android.os.ParcelFileDescriptor tun=new android.os.ParcelFileDescriptor();
   field("externalOwner").setBoolean(s,true);field("externalSession").set(s,f.session);field("externalHomeOwner").set(s,home(true));field("commandServer").set(s,f.server);field("tunDescriptor").set(s,tun);field("activeSession").set(s,folder.toFile());field("activeMode").set(s,"standard-direct-socks5");field("state").set(s,"UP");field("executionProved").setBoolean(s,true);field("connectivity").set(s,new android.net.ConnectivityManager());field("executionNetwork").set(s,invoke(s,"executionNetworkIdentity",new Class<?>[0]));
   if(replacement){AndroidHomeStateStore.Snapshot newer=home(true);newer.sessionId="newer-owner";}
   Libbox.externalCreated.alive=false;((Runnable)field("executionWatch").get(s)).run();drain(s);
   check(replacement?AndroidHomeStateStore.value.connected:!AndroidHomeStateStore.value.connected,"external failure changed wrong Home or left stale Connected");check(replacement?AndroidHomeStateStore.value.sessionId.equals("newer-owner"):AndroidHomeStateStore.value.pathProof.equals("failed"),"external failure adopted stale proof");check(tun.closed&&!Files.exists(folder)&&field("commandServer").get(s)==null,"failed external owner did not clean native/session state");s.onDestroy();
  }
  Libbox.externalReset();LayeredVpnService s=new LayeredVpnService();AndroidHomeStateStore.Snapshot captured=home(true);field("externalHomeOwner").set(s,captured);field("externalOwner").setBoolean(s,true);CommandServer server=new CommandServer(s,s);field("commandServer").set(s,server);Libbox.failClose=true;
  reject(()->invoke(s,"shutdown",new Class<?>[]{String.class,String.class},"FAILED","Lost external DNS proof"));check(!captured.connected&&captured.pathProof.equals("failed")&&!captured.activeExternalId.isEmpty(),"unconfirmed close left Connected or lost Home owner");check(field("externalHomeOwner").get(s)==captured&&field("commandServer").get(s)==server,"failed native drain lost exact Home/native identity");
  Libbox.failClose=false;invoke(s,"shutdown",new Class<?>[]{String.class,String.class},"FAILED","Lost external DNS proof");check(captured.activeExternalId.isEmpty()&&field("externalHomeOwner").get(s)==null,"successful close retained released external identity");s.onDestroy();
 }
 static void preparedFiles()throws Exception{
  LayeredVpnService s=new LayeredVpnService();s.files=Files.createTempDirectory("external-preflight-").toFile();s.onCreate();Path root=s.files.toPath().resolve("layered-sessions");Files.createDirectories(root);android.net.VpnService.lockdown=false;
  for(int i=0;i<40;i++){String id="denied-"+i;Path folder=root.resolve(id);Files.createDirectory(folder);Files.writeString(folder.resolve(AndroidKillSwitchPolicy.SESSION_MARKER),"1");invoke(s,"startLayered",new Class<?>[]{String.class,String.class,long.class,String.class,String.class},id,"standard-direct-socks5",0L,"","home-owned");check(!Files.exists(folder),"denied lockdown leaked prepared directory "+i);}
  android.net.VpnService.lockdown=true;Path live=root.resolve("live"),pending=root.resolve("cancelled"),outside=s.files.toPath().resolve("outside");Files.createDirectory(live);Files.createDirectory(pending);Files.writeString(outside,"retain");field("activeSession").set(s,live.toFile());
  check(!LayeredVpnService.discardPreparedSession(s,"live")&&Files.exists(live),"discard released an active native directory");check(LayeredVpnService.discardPreparedSession(s,"cancelled")&&!Files.exists(pending),"unclaimed cancelled preparation retained");check(!LayeredVpnService.discardPreparedSession(s,"../outside")&&Files.exists(outside),"discard escaped private session root");
  Path link=root.resolve("link");Files.createSymbolicLink(link,outside);check(!LayeredVpnService.discardPreparedSession(s,"link")&&Files.exists(outside),"discard followed a foreign root symlink");Files.delete(link);
  Path stopped=root.resolve("late-start");Files.createDirectory(stopped);field("explicitStop").setBoolean(s,true);invoke(s,"startLayered",new Class<?>[]{String.class,String.class,long.class,String.class,String.class},"late-start","standard-direct-socks5",0L,"","home-owned");check(!Files.exists(stopped),"retired queued launch leaked preparation");s.onDestroy();
 }
 static void automaticMTU()throws Exception{
  for(String changed:new String[]{"live","pending","session","exit","home","proof","generation","replaced"}){
   Libbox.externalReset();Fixture f=new Fixture(false);f.session.prove();LayeredVpnService s=new LayeredVpnService();s.files=Files.createTempDirectory("external-mtu-adoption-").toFile();s.onCreate();
   AndroidHomeStateStore.Snapshot captured=home(false);field("externalHomeOwner").set(s,captured);home(true);
   AndroidMTUSession mtu=new AndroidMTUSession(s,owner->{});field("mtuSession").set(s,mtu);field("commandServer").set(s,f.server);field("externalSession").set(s,f.session);field("state").set(s,"UP");
   java.util.concurrent.ExecutorService worker=(java.util.concurrent.ExecutorService)field("executor").get(s);CountDownLatch entered=new CountDownLatch(1),release=new CountDownLatch(1);worker.submit(()->{entered.countDown();try{release.await();}catch(Exception e){throw new AssertionError(e);}});waitFor(entered);
   if(changed.equals("pending"))home(false);if(changed.equals("proof"))Libbox.externalCreated.alive=false;
   LayeredVpnService.startExternalAutomaticMTU(changed.equals("session")?"other":"session-owned",changed.equals("exit")?"other":"exit-owned",changed.equals("home")?"other":"home-owned");
   if(changed.equals("generation"))((AtomicLong)field("lifecycle").get(s)).incrementAndGet();if(changed.equals("replaced"))field("externalSession").set(s,null);
   release.countDown();drain(s);check(mtu.externalStarts==(changed.equals("live")?1:0),"MTU activation adopted a pending or replaced external path: "+changed);
   if(changed.equals("live"))check(mtu.activatedExternal==f.session&&!captured.connected,"MTU did not follow retained proof and current immutable Home snapshot");s.onDestroy();
  }
  LayeredVpnService s=new LayeredVpnService();AndroidMTUSession mtu=new AndroidMTUSession(s,owner->{});mtu.closeFailures=1;android.os.ParcelFileDescriptor tun=new android.os.ParcelFileDescriptor();field("mtuSession").set(s,mtu);field("tunDescriptor").set(s,tun);AndroidHomeStateStore.Snapshot captured=home(true);field("externalHomeOwner").set(s,captured);field("externalOwner").setBoolean(s,true);field("commandServer").set(s,new CommandServer(s,s));
  reject(()->close(s));check(field("mtuSession").get(s)==mtu&&!tun.closed&&mtu.closes==1&&field("externalHomeOwner").get(s)==captured,"unconfirmed MTU cleanup discarded the only native, Home or TUN owner");close(s);check(field("mtuSession").get(s)==null&&tun.closed&&mtu.closes==2&&field("externalHomeOwner").get(s)==null,"successful MTU cleanup retry did not release its owner");s.onDestroy();
 }
 public static void main(String[]args)throws Exception{try{success();rejection();cancellation();serviceOwner();homeCapture();failedHome();preparedFiles();automaticMTU();System.out.println("Android external proof/service lifecycle: "+checks+" executable checks passed");}catch(Throwable failure){failure.printStackTrace();System.exit(1);}}
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
            ("LayeredVpnService.java", "AndroidHomeStateStore.failedPolicyExternal(this,home,error.isEmpty()?\"The captured external VPN is stopping; its path proof is no longer valid.\":error,false);", "", "Home invalidation before native drain"),
            ("LayeredVpnService.java", "discardPreparedSession(this,sessionId);\n        }\n    }", "\n        }\n    }", "preflight preparation cleanup"),
            ("LayeredVpnService.java", "generation!=service.lifecycle.get()||", "", "queued external MTU generation"),
            ("LayeredVpnService.java", 'if(service.externalSession!=external||home==null||!now.connected||!"passed".equals(now.pathProof)||!external.healthy()', 'if(home==null||!now.connected||!"passed".equals(now.pathProof)||!external.healthy()', "queued external MTU native owner"),
            ("LayeredVpnService.java", 'catch(Exception error){publish("STOPPING",activeMode,"MTU cleanup is still pending; its native owner is retained.");throw new IllegalStateException("MTU controller teardown has not drained.");}', "catch(Exception error){}", "retained failed MTU cleanup"),
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
        print("Android external owner negative controls: 8 rejected")


if __name__ == "__main__":
    main()
