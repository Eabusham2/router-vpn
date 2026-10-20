#!/usr/bin/env python3
"""Execute the real Tor proof binder and full VpnService close boundary.

Only OS and Libbox handles are doubled. Native Tor traffic, generated graphs and
physical worker drains have separate pinned gates; this proves Java ownership.
"""
from pathlib import Path
import importlib.util
import os
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
JAVA = ROOT / 'android/app/src/main/java/com/eabusham/routervpn'
spec = importlib.util.spec_from_file_location('tor_service_types', ROOT/'android/test_android_layered_service_compile.py')
B = importlib.util.module_from_spec(spec); spec.loader.exec_module(B)
SOURCES = dict(B.STUBS)
SOURCES.pop('org/json/JSONObject.java')
SOURCES.pop('com/eabusham/routervpn/AndroidTorSession.java')
SOURCES['com/eabusham/routervpn/AndroidTorProfile.java'] = '''package com.eabusham.routervpn;
final class AndroidTorProfile {
 static final String OUTBOUND="routervpn-tor-exit",SESSION_FILE="routervpn-tor.json";static final int MAX_METADATA=262144;
 static org.json.JSONObject session(String c,String m,String s,String mode)throws Exception{return new org.json.JSONObject(m);}
 static String strictText(byte[] b)throws Exception{return new String(b,java.nio.charset.StandardCharsets.UTF_8);}
}'''
SOURCES['android/content/Context.java'] = SOURCES['android/content/Context.java'].replace('return null;} public android.content.pm.PackageManager', '''return new SharedPreferences(){public Editor edit(){return new Editor(){public Editor putString(String a,String b){return this;}public void apply(){}};}};} public android.content.pm.PackageManager''')
SOURCES['android/os/ParcelFileDescriptor.java'] = '''package android.os;
public class ParcelFileDescriptor implements java.io.Closeable {public boolean closed;public static ParcelFileDescriptor duplicate;public static ParcelFileDescriptor fromFd(int fd){duplicate=new ParcelFileDescriptor();return duplicate;}public java.io.FileDescriptor getFileDescriptor(){return new java.io.FileDescriptor();}public int getFd(){return 1;}public void close(){closed=true;}}'''
SOURCES['android/net/Network.java'] = '''package android.net;
public class Network {public int fdBinds,tcpBinds,udpBinds;public void bindSocket(java.io.FileDescriptor fd){fdBinds++;}public void bindSocket(java.net.Socket s){tcpBinds++;}public void bindSocket(java.net.DatagramSocket s){udpBinds++;}}'''
SOURCES['android/net/ConnectivityManager.java'] = SOURCES['android/net/ConnectivityManager.java'].replace('public Network[] getAllNetworks(){return new Network[0];}', 'public static Network[] networks=new Network[0];public Network[] getAllNetworks(){return networks;}').replace('getNetworkCapabilities(Network n){return null;}', 'getNetworkCapabilities(Network n){return java.util.Arrays.asList(networks).contains(n)?new NetworkCapabilities():null;}').replace('getLinkProperties(Network n){return null;}', 'getLinkProperties(Network n){return new LinkProperties();}')
SOURCES['com/eabusham/routervpn/AndroidStartLayerRelay.java'] = SOURCES['com/eabusham/routervpn/AndroidStartLayerRelay.java'].replace('public void close(){}', 'public boolean pending;public int closes;public void close(){closes++;if(pending)throw new IllegalStateException("unfinished relay workers");}')
SOURCES['io/nekohasekai/libbox/CommandServer.java'] = '''package io.nekohasekai.libbox;
public class CommandServer {public int closes,uncheckedCloses;public CommandServer(PlatformInterface p,CommandServerHandler h){}public void start(){}public void startOrReloadService(String c,OverrideOptions o){}public void closeService(){uncheckedCloses++;}public void close(){closes++;}public void resetNetwork(){}}'''
SOURCES['io/nekohasekai/libbox/RouterTorProofRequest.java'] = r'''package io.nekohasekai.libbox;
import java.util.concurrent.*;import java.util.concurrent.atomic.*;import org.json.*;import java.time.*;
public class RouterTorProofRequest {
 public final CommandServer server;public final String session,predecessor;
 public final AtomicInteger cancels=new AtomicInteger();public volatile boolean alive=true,ran,ignoreCancellation;
 public volatile String response;public volatile CountDownLatch entered,release;
 public RouterTorProofRequest(CommandServer s,String id,String p){server=s;session=id;predecessor=p;}
 public String run()throws Exception {if(entered!=null){entered.countDown();release.await();}ran=true;
  if(!alive&&!ignoreCancellation)throw new IllegalStateException("cancelled");
  return response!=null?response:new JSONObject().put("session_id",session).put("is_tor",true).put("ip","8.8.4.4").put("checked_at",Instant.now().toString()).toString();}
 public void cancel(){cancels.incrementAndGet();if(!ignoreCancellation){alive=false;if(release!=null)release.countDown();if(Libbox.dnsRelease!=null)Libbox.dnsRelease.countDown();}}
 public boolean healthy(){return alive&&ran;}
}'''
LIBBOX = SOURCES['io/nekohasekai/libbox/Libbox.java']
LIBBOX = LIBBOX.replace('public static void routerStrategyCloseService(CommandServer server)throws Exception{}', 'public static void routerStrategyCloseService(CommandServer server)throws Exception{checkedCloses++;if(failClose)throw new IllegalStateException("unconfirmed native drain");}')
LIBBOX = LIBBOX[:-1] + r'''
 public static volatile RouterTorProofRequest next,created;public static volatile int dnsCalls,checkedCloses;
 public static volatile boolean failClose,dnsFailure;public static volatile java.util.concurrent.CountDownLatch factoryEntered,factoryRelease,dnsEntered,dnsRelease;
 public static void reset(){next=null;created=null;dnsCalls=0;checkedCloses=0;failClose=false;dnsFailure=false;factoryEntered=null;factoryRelease=null;dnsEntered=null;dnsRelease=null;}
 public static RouterTorProofRequest routerTorCreateProof(CommandServer s,String tag,String id)throws Exception{return make(s,tag,id,"");}
 public static RouterTorProofRequest routerTorCreateProofWithPredecessor(CommandServer s,String tag,String id,String p)throws Exception{return make(s,tag,id,p);}
 private static RouterTorProofRequest make(CommandServer s,String tag,String id,String p)throws Exception{
  if(!tag.equals("routervpn-tor-exit"))throw new AssertionError("wrong Tor tag");RouterTorProofRequest r=next==null?new RouterTorProofRequest(s,id,p):next;created=r;
  if(factoryEntered!=null){factoryEntered.countDown();factoryRelease.await();}return r;
 }
 public static void routerStrategyDNSProof(CommandServer s)throws Exception{dnsCalls++;if(s!=created.server)throw new AssertionError("DNS used another native Box");if(dnsEntered!=null){dnsEntered.countDown();dnsRelease.await();}if(dnsFailure)throw new IllegalStateException("DNS failed");}
 public static RouterHopMeasurement routerTorCreateHopMeasurement(CommandServer s,RouterTorProofRequest proof,String id)throws Exception{return new RouterHopMeasurement();}
}'''
SOURCES['io/nekohasekai/libbox/Libbox.java'] = LIBBOX
HARNESS = r'''package com.eabusham.routervpn;
import org.json.*;import io.nekohasekai.libbox.*;import java.time.*;import java.util.concurrent.*;import java.util.concurrent.atomic.*;import java.lang.reflect.*;import java.nio.file.*;
public final class TorSessionHarness {
 static int checks;static void check(boolean ok,String message){checks++;if(!ok)throw new AssertionError(message);}
 interface Attempt{void run()throws Exception;}
 static void rejected(Attempt task)throws Exception{boolean failed=false;try{task.run();}catch(Exception expected){failed=true;}check(failed,"unowned Tor success escaped");}
 static void waitFor(CountDownLatch latch)throws Exception{check(latch.await(2,TimeUnit.SECONDS),"boundary was not reached");}
 static final class Fixture implements AndroidTorSession.Owner {
  CommandServer server=new CommandServer(null,null);volatile CommandServer currentServer=server;volatile String network="wifi-1";volatile AndroidTorSession session;
  Fixture(boolean predecessor)throws Exception{JSONObject m=new JSONObject().put("session_id","session-owned").put("external_id","exit-owned");if(predecessor)m.put("predecessor_profile",new JSONObject().put("id","private-entry").put("api_token","captured-private-token"));session=new AndroidTorSession(m,server,this);}
  public boolean current(AndroidTorSession s,CommandServer c){return s==session&&c==currentServer;}
  public String network(){return network;}
  RouterTorProofRequest blocked(boolean ignore){RouterTorProofRequest r=new RouterTorProofRequest(server,"session-owned","");r.entered=new CountDownLatch(1);r.release=new CountDownLatch(1);r.ignoreCancellation=ignore;Libbox.next=r;return r;}
 }
 static final class Job {final AtomicReference<Throwable> error=new AtomicReference<>();final Thread thread;
  Job(Fixture f){thread=new Thread(()->{try{f.session.prove();}catch(Throwable t){error.set(t);}},"captured-tor-proof");thread.start();}
  void finish(boolean failed)throws Exception{thread.join(2000);check(!thread.isAlive(),"proof worker escaped its join");check((error.get()!=null)==failed,"proof adopted stale completion");}
 }
 static void successes()throws Exception{
  for(boolean entry:new boolean[]{false,true}){Libbox.reset();Fixture f=new Fixture(entry);check(!f.session.healthy(),"unproven session healthy");rejected(()->f.session.result("session-owned","exit-owned"));f.session.prove();
   check(f.session.healthy()&&Libbox.dnsCalls==1,"circuit and uncached DNS not proved");check(!Libbox.created.predecessor.isEmpty()==entry,"entry proof factory dropped captured profile");
   if(entry)check(Libbox.created.predecessor.contains("captured-private-token"),"entry authentication capture lost");
   check(new JSONObject(f.session.result("session-owned","exit-owned")).getString("ip").equals("8.8.4.4"),"Tor exit mismatch");
   rejected(()->f.session.result("other","exit-owned"));rejected(()->f.session.result("session-owned","other"));rejected(f.session::prove);
   Libbox.created.alive=false;check(!f.session.healthy(),"dead native owner stayed healthy");check(Libbox.dnsCalls==1,"health started another proof");}
 }
 static void responses()throws Exception{
  for(String field:new String[]{"session","false","typed","private4","private6","loopback","hostname","legacy","mapped","empty","stale","future","extra","missing","oversized"}){
   Libbox.reset();Fixture f=new Fixture(false);RouterTorProofRequest r=new RouterTorProofRequest(f.server,"session-owned","");Libbox.next=r;
   JSONObject p=new JSONObject().put("session_id","session-owned").put("is_tor",true).put("ip","8.8.8.8").put("checked_at",Instant.now().toString());
   switch(field){case "session":p.put("session_id","other");break;case "false":p.put("is_tor",false);break;case "typed":p.put("is_tor","true");break;
    case "private4":p.put("ip","10.0.0.1");break;case "private6":p.put("ip","fd00::1");break;case "loopback":p.put("ip","127.0.0.1");break;case "hostname":p.put("ip","must-not-resolve.example");break;case "legacy":p.put("ip","010.1.2.3");break;case "mapped":p.put("ip","::ffff:8.8.8.8");break;case "empty":p.put("ip","");break;
    case "stale":p.put("checked_at",Instant.now().minusSeconds(60).toString());break;case "future":p.put("checked_at",Instant.now().plusSeconds(120).toString());break;
    case "extra":p.put("other","foreign");break;case "missing":p.remove("checked_at");break;case "oversized":p.put("ip","x".repeat(5000));break;}
   r.response=p.toString();rejected(f.session::prove);check(!f.session.healthy(),"invalid native proof healthy: "+field);check(Libbox.dnsCalls==0,"DNS started before valid Tor proof: "+field);
  }
  Libbox.reset();Fixture f=new Fixture(false);Libbox.dnsFailure=true;rejected(f.session::prove);check(!f.session.healthy(),"failed DNS admitted Connected");
 }
 static void cancellation()throws Exception{
  Libbox.reset();Fixture never=new Fixture(false);never.session.cancel();rejected(never.session::prove);check(Libbox.created==null,"cancelled session created new native owner");
  for(boolean ignore:new boolean[]{false,true}){Libbox.reset();Fixture f=new Fixture(false);RouterTorProofRequest r=f.blocked(ignore);Job job=new Job(f);waitFor(r.entered);long began=System.nanoTime();f.session.cancel();check(System.nanoTime()-began<250000000L,"Cancel blocked on native proof");check(r.cancels.get()==1,"Cancel missed captured handle");
   if(ignore){check(job.thread.isAlive(),"late native work was falsely joined");r.release.countDown();}job.finish(true);check(!f.session.healthy()&&Libbox.dnsCalls==0,"cancelled proof started DNS");}
  Libbox.reset();Fixture factory=new Fixture(false);Libbox.factoryEntered=new CountDownLatch(1);Libbox.factoryRelease=new CountDownLatch(1);Job creating=new Job(factory);waitFor(Libbox.factoryEntered);RouterTorProofRequest first=Libbox.created;factory.session.cancel();factory.currentServer=new CommandServer(null,null);Libbox.factoryRelease.countDown();creating.finish(true);check(first.cancels.get()==1&&!first.ran,"late factory escaped captured cancel");
  for(String change:new String[]{"cancel","network","server","native"}){Libbox.reset();Fixture f=new Fixture(false);RouterTorProofRequest r=new RouterTorProofRequest(f.server,"session-owned","");r.ignoreCancellation=true;Libbox.next=r;Libbox.dnsEntered=new CountDownLatch(1);Libbox.dnsRelease=new CountDownLatch(1);Job job=new Job(f);waitFor(Libbox.dnsEntered);
   if(change.equals("cancel"))f.session.cancel();if(change.equals("network"))f.network="cellular-2";if(change.equals("server"))f.currentServer=new CommandServer(null,null);if(change.equals("native"))r.alive=false;
   Libbox.dnsRelease.countDown();job.finish(true);check(!f.session.healthy(),"DNS completed into a stale "+change+" owner");}
  Libbox.reset();Fixture f=new Fixture(false);RouterTorProofRequest r=f.blocked(true);Job job=new Job(f);waitFor(r.entered);f.network="cellular-2";r.release.countDown();job.finish(true);check(Libbox.dnsCalls==0,"changed network reached DNS");
 }
 static Field field(String name)throws Exception{Field f=LayeredVpnService.class.getDeclaredField(name);f.setAccessible(true);return f;}
 static void close(LayeredVpnService service)throws Exception{Method m=LayeredVpnService.class.getDeclaredMethod("closeCoreLocked");m.setAccessible(true);try{m.invoke(service);}catch(InvocationTargetException e){throw (Exception)e.getCause();}}
 static void retainedClose()throws Exception{
  Libbox.reset();LayeredVpnService service=new LayeredVpnService();CommandServer server=new CommandServer(service,service);android.os.ParcelFileDescriptor tun=new android.os.ParcelFileDescriptor();
  Path folder=Files.createTempDirectory("tor-owned-java-");Files.writeString(folder.resolve("keep"),"owned metadata");field("torOwner").set(service,true);field("commandServer").set(service,server);field("tunDescriptor").set(service,tun);field("activeSession").set(service,folder.toFile());field("activeMode").set(service,"standard-direct-tor");
  Libbox.failClose=true;rejected(()->close(service));check(field("commandServer").get(service)==server&&field("torOwner").getBoolean(service),"unconfirmed Box was forgotten");
  check(!tun.closed&&field("tunDescriptor").get(service)==tun&&Files.exists(folder.resolve("keep")),"unconfirmed native drain released VPN or session");
  check(server.closes==0&&server.uncheckedCloses==0,"unchecked close bypassed quarantine");check(field("state").get(service).equals("STOPPING"),"unconfirmed drain reported terminal state");
  Libbox.failClose=false;close(service);check(field("commandServer").get(service)==null&&!field("torOwner").getBoolean(service),"proved close did not release owner");check(tun.closed&&server.closes==1&&server.uncheckedCloses==0&&Libbox.checkedCloses==2,"retained close did not retry exact Box");service.onDestroy();check(!Files.exists(folder),"proved shutdown retained temporary session");
 }
 static void physicalNetwork()throws Exception{
  Libbox.reset();LayeredVpnService service=new LayeredVpnService();android.net.Network captured=new android.net.Network();android.net.ConnectivityManager.networks=new android.net.Network[]{captured};field("connectivity").set(service,new android.net.ConnectivityManager());field("torPhysicalNetwork").set(service,captured);field("torOwner").setBoolean(service,true);
  Method identity=LayeredVpnService.class.getDeclaredMethod("executionNetworkIdentity");identity.setAccessible(true);field("executionNetwork").set(service,identity.invoke(service));
  service.autoDetectInterfaceControl(123);check(captured.fdBinds==1,"native Tor FD was not bound to its captured network");check(android.os.ParcelFileDescriptor.duplicate.closed,"borrowed descriptor duplicate was leaked");
  service.protectRelaySocket(new java.net.Socket());service.protectRelaySocket((java.net.DatagramSocket)null);check(captured.tcpBinds==1&&captured.udpBinds==1,"Start Layer sockets escaped the captured physical network");
  android.net.ConnectivityManager.networks=new android.net.Network[]{new android.net.Network()};rejected(()->service.autoDetectInterfaceControl(124));rejected(()->service.protectRelaySocket(new java.net.Socket()));check(captured.fdBinds==1&&captured.tcpBinds==1,"changed network admitted a new protected dial");
  field("torOwner").setBoolean(service,false);service.autoDetectInterfaceControl(125);check(captured.fdBinds==1,"ordinary graph inherited a previous Tor network");service.onDestroy();
 }
 static void retainedRelayClose()throws Exception{
  Libbox.reset();LayeredVpnService service=new LayeredVpnService();CommandServer server=new CommandServer(service,service);android.os.ParcelFileDescriptor tun=new android.os.ParcelFileDescriptor();AndroidStartLayerRelay relay=new AndroidStartLayerRelay();relay.pending=true;
  field("torOwner").setBoolean(service,true);field("commandServer").set(service,server);field("tunDescriptor").set(service,tun);field("startLayerRelay").set(service,relay);
  rejected(()->close(service));check(Libbox.checkedCloses==0&&server.closes==0,"native owner was released before its Java lower worker joined");check(field("torOwner").getBoolean(service)&&field("startLayerRelay").get(service)==relay&&!tun.closed,"unconfirmed relay close released its graph or TUN");
  check(field("state").get(service).equals("STOPPING"),"unfinished Java lower reported terminal state");relay.pending=false;close(service);check(relay.closes==2&&Libbox.checkedCloses==1&&tun.closed,"retry did not drain the retained relay before its exact native Box");check(field("startLayerRelay").get(service)==null,"proved relay drain retained a stale owner");service.onDestroy();
 }
 public static void main(String[] args)throws Exception{successes();responses();cancellation();retainedClose();physicalNetwork();retainedRelayClose();System.out.println("Android captured Tor proof/service lifecycle: PASS "+checks+" checks (native and OS handles doubled)");}
}'''


def main():
    jar=Path(os.environ.get('ANDROID_JSON_JAR','/usr/share/java/com.android.json.jar'))
    if not jar.is_file() or not shutil.which('javac'):raise RuntimeError('JDK and Android JSON implementation are required')
    with tempfile.TemporaryDirectory(prefix='routervpn-tor-java-owner-') as directory:
        folder=Path(directory)
        for name,source in SOURCES.items():
            path=folder/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_text(source)
        for name in ('AndroidTorSession','AndroidNumericAddress','LayeredVpnService'):
            shutil.copyfile(JAVA/(name+'.java'),folder/'com/eabusham/routervpn'/(name+'.java'))
        (folder/'com/eabusham/routervpn/TorSessionHarness.java').write_text(HARNESS)
        sources=list(map(str,folder.rglob('*.java')));classes=folder/'classes'
        compile_args=['javac','--release','17','-encoding','UTF-8','-proc:none','-cp',str(jar),'-d',str(classes),*sources]
        run_args=['java','-cp',os.pathsep.join((str(classes),str(jar))),'com.eabusham.routervpn.TorSessionHarness']
        subprocess.run(compile_args,check=True,timeout=45);subprocess.run(run_args,check=True,timeout=20)
        controls=[('AndroidTorSession.java','''            if (cancelled || !current() || !captured.healthy()) throw unavailable();
            result = response;''','''            result = response;''','DNS completion owner check'),
                  ('LayeredVpnService.java','Libbox.routerStrategyCloseService(commandServer);','commandServer.closeService();','checked native close'),
                  ('LayeredVpnService.java','captured.bindSocket(borrowed.getFileDescriptor());','','captured physical network binding')]
        for name,old,new,label in controls:
            path=folder/'com/eabusham/routervpn'/name;original=path.read_text();assert original.count(old)==1,label
            path.write_text(original.replace(old,new));subprocess.run(compile_args,check=True,timeout=45)
            result=subprocess.run(run_args,capture_output=True,text=True,timeout=20);assert result.returncode!=0 and 'AssertionError' in result.stderr,label+' control escaped'
            path.write_text(original)
        print('Android Tor lifecycle negative controls: PASS (late DNS adoption, unchecked close and lost network binding rejected)')


if __name__=='__main__':main()
