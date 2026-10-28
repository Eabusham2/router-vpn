#!/usr/bin/env python3
"""Run shipping DNS session, VpnService, receipt and worker against native handle doubles.

Real encrypted DNS traffic and actual Box/router ownership are covered by the
shared/pinned gates. No public socket or VPN is opened by these Java checks.
"""
from pathlib import Path
import importlib.util
import os
import shutil
import subprocess
import tempfile

ROOT=Path(__file__).resolve().parents[1]
JAVA=ROOT/"android/app/src/main/java/com/eabusham/routervpn"
spec=importlib.util.spec_from_file_location("dns_hop_boundaries",ROOT/"android/test_android_external_hop_measurement.py")
T=importlib.util.module_from_spec(spec);spec.loader.exec_module(T)
SOURCES=dict(T.SOURCES)
SOURCES["io/nekohasekai/libbox/RouterDNSMeasurement.java"]=r'''package io.nekohasekai.libbox;
public class RouterDNSMeasurement {
 public volatile int closes,invalidations,starts,cancels,drains;public volatile String request="",transport="";public boolean closePending,failStart;public Runnable onStart,onStatus;
 public volatile java.util.concurrent.CountDownLatch drainEntered,drainRelease;
 public java.util.function.Supplier<String> response;
 private final java.util.Set<String> retired=java.util.concurrent.ConcurrentHashMap.newKeySet();
 public void close(){closes++;if(closePending)throw new IllegalStateException("native worker pending");}public void networkChanged(){invalidations++;}
 public void start(String id,String mode){starts++;if(failStart)throw new IllegalStateException("native activity busy");if(retired.contains(id))throw new IllegalStateException("cancelled nonce");request=id;transport=mode;if(onStart!=null)onStart.run();}
 public void cancel(String id){retired.add(id);cancels++;}
 public void drain(String id){if(!id.equals(request)&&!retired.contains(id))throw new AssertionError("unknown DNS drain");drains++;if(drainEntered!=null)drainEntered.countDown();if(drainRelease!=null&&drainRelease.getCount()!=0)throw new IllegalStateException("native DNS socket pending");}
 public String statusJSON(){if(onStatus!=null)onStatus.run();return response==null?"{\"schema\":1,\"request_id\":\""+request+"\",\"node_id\":\"exit-owned\",\"session_id\":\"session-owned\",\"public_transport\":\""+transport+"\",\"stage\":\"measuring\",\"complete\":false,\"drained\":false,\"results\":[]}":response.get();}
}'''
native=SOURCES["io/nekohasekai/libbox/Libbox.java"]
native=native.replace('public static RouterDNSMeasurement routerTorCreateDNSMeasurement(CommandServer s,RouterTorProofRequest proof,String id)throws Exception{return new RouterDNSMeasurement();}', 'public static RouterDNSMeasurement routerTorCreateDNSMeasurement(CommandServer s,RouterTorProofRequest proof,String id)throws Exception{return makeDNSMeasurement(s,proof,"","",id);}')
native=native.replace('public static RouterDNSMeasurement routerExternalCreateDNSMeasurement(CommandServer s,RouterExternalProofRequest proof,String source,String capture,String id)throws Exception{return new RouterDNSMeasurement();}', 'public static RouterDNSMeasurement routerExternalCreateDNSMeasurement(CommandServer s,RouterExternalProofRequest proof,String source,String capture,String id)throws Exception{return makeDNSMeasurement(s,proof,source,capture,id);}')
SOURCES["io/nekohasekai/libbox/Libbox.java"]=native[:-1]+r'''
 public static volatile CommandServer dnsMeasurementServer;public static volatile Object dnsMeasurementProof;
 public static volatile String dnsMeasurementSource,dnsMeasurementCapture,dnsMeasurementID;
 public static volatile RouterDNSMeasurement dnsMeasurementCreated;public static int dnsMeasurementCalls;
 public static volatile boolean dnsMeasurementNull;public static volatile java.util.concurrent.CountDownLatch dnsMeasurementEntered,dnsMeasurementRelease;
 public static void dnsMeasurementReset(){measurementReset();dnsMeasurementServer=null;dnsMeasurementProof=null;dnsMeasurementSource="";dnsMeasurementCapture="";dnsMeasurementID="";dnsMeasurementCreated=null;dnsMeasurementCalls=0;dnsMeasurementNull=false;dnsMeasurementEntered=null;dnsMeasurementRelease=null;}
 private static RouterDNSMeasurement makeDNSMeasurement(CommandServer s,Object p,String source,String capture,String id)throws Exception{
  dnsMeasurementCalls++;dnsMeasurementServer=s;dnsMeasurementProof=p;dnsMeasurementSource=source;dnsMeasurementCapture=capture;dnsMeasurementID=id;
  RouterDNSMeasurement m=dnsMeasurementNull?null:new RouterDNSMeasurement();dnsMeasurementCreated=m;
  if(dnsMeasurementEntered!=null){dnsMeasurementEntered.countDown();dnsMeasurementRelease.await();}return m;
 }
}'''
# Exercise the existing exact-proof and late-factory cases with the new native
# factory too. The shipping Java implementation is copied, never reconstructed.
HARNESS=T.HARNESS.split(" static void serviceAdoption()throws Exception{")[0]
HARNESS=HARNESS.replace("ExternalHopMeasurementTest","ExternalDNSMeasurementTest").replace("RouterHopMeasurement","RouterDNSMeasurement").replace("newHopMeasurement","newDNSMeasurement").replace("adoptHopMeasurement","adoptDNSMeasurement").replace("Libbox.measurement","Libbox.dnsMeasurement")
HARNESS+=r'''
 static LayeredVpnService live(Fixture f,RouterDNSMeasurement probe)throws Exception{
  LayeredVpnService s=service(f.server);field(f.isTor?"torSession":"externalSession").set(s,f.isTor?f.tor:f.external);adopt(s,probe,f.server,0);
  field("state").set(s,"UP");field("currentService").set(null,new java.lang.ref.WeakReference<>(s));return s;
 }
 static void serviceAdoption()throws Exception{
  for(boolean tor:new boolean[]{false,true})for(String reason:new String[]{"valid","stop","generation","server","network","existing","proof"}){
   Libbox.dnsMeasurementReset();Fixture f=new Fixture(tor,true);f.prove();RouterDNSMeasurement captured=f.create(),old=new RouterDNSMeasurement();LayeredVpnService s=service(f.server);
   field(tor?"torSession":"externalSession").set(s,tor?f.tor:f.external);long generation=0;
   if(reason.equals("stop"))field("explicitStop").setBoolean(s,true);if(reason.equals("generation"))generation=1;if(reason.equals("server"))field("commandServer").set(s,new CommandServer(null,null));if(reason.equals("network"))field("executionNetwork").set(s,"old-network");if(reason.equals("existing"))field("dnsMeasurement").set(s,old);if(reason.equals("proof"))f.cancel();
   final long selected=generation;
   if(reason.equals("valid")){adopt(s,captured,f.server,selected);check(field("dnsMeasurement").get(s)==captured&&captured.closes==0,"DNS handle not adopted");}
   else {reject(()->adopt(s,captured,f.server,selected));check(captured.closes==1,"rejected DNS handle leaked");if(reason.equals("existing"))check(field("dnsMeasurement").get(s)==old,"existing DNS handle replaced");}
   s.onDestroy();
  }
  Libbox.dnsMeasurementReset();Fixture f=new Fixture(true,true);f.prove();RouterDNSMeasurement probe=f.create();LayeredVpnService s=live(f,probe);field("torOwner").setBoolean(s,true);probe.closePending=true;
  reject(()->invoke(s,"closeCoreLocked",new Class<?>[]{}));check(field("dnsMeasurement").get(s)==probe&&field("commandServer").get(s)==f.server&&field("torSession").get(s)==f.tor,"pending DNS cleanup released native owner");probe.closePending=false;invoke(s,"closeCoreLocked",new Class<?>[]{});check(field("dnsMeasurement").get(s)==null&&probe.closes==2,"DNS retained close was not retried");s.onDestroy();
 }
 static void requests()throws Exception{
  String id="1234567890abcdef1234567890abcdef";
  for(String reason:new String[]{"valid","generation","server","network","replacement","stop","state","proof","late-start","late-status"}){
   Libbox.dnsMeasurementReset();Fixture f=new Fixture(true,false);f.prove();RouterDNSMeasurement probe=f.create();LayeredVpnService s=live(f,probe);
   reject(()->LayeredVpnService.captureDNSMeasurement(id,"another-exit"));LayeredVpnService.DNSMeasurementOwner owner=LayeredVpnService.captureDNSMeasurement(id,"exit-owned");check(!owner.attempted(),"capture started DNS traffic");
   AtomicLong generation=(AtomicLong)field("lifecycle").get(s);if(reason.equals("late-start"))probe.onStart=()->generation.incrementAndGet();
   if(reason.equals("late-start")){reject(()->owner.start("tls"));check(owner.attempted(),"late native Start was abandoned");}else owner.start("tls");
   if(reason.equals("generation"))generation.incrementAndGet();if(reason.equals("server"))field("commandServer").set(s,new CommandServer(null,null));if(reason.equals("network"))android.net.ConnectivityManager.networks=new android.net.Network[]{};if(reason.equals("replacement"))field("dnsMeasurement").set(s,new RouterDNSMeasurement());if(reason.equals("stop"))field("explicitStop").setBoolean(s,true);if(reason.equals("state"))field("state").set(s,"STOPPING");if(reason.equals("proof"))f.cancel();if(reason.equals("late-status"))probe.onStatus=()->generation.incrementAndGet();
   if(reason.equals("valid"))check(new JSONObject(owner.status()).getString("request_id").equals(id),"DNS owner request changed");else reject(owner::status);
   owner.cancel();owner.drain();check(probe.cancels==1&&probe.drains==1,"old DNS owner could not cancel/drain after replacement");field("dnsMeasurement").set(s,probe);s.onDestroy();
  }
 }
 public static JSONObject receipt(String id,String transport)throws Exception{
  String[] ids={"cf4a","cf4b","cf6a","cf6b","g4a","g4b","g6a","g6b","q4a","q4b","q6a","q6b"},addresses={"1.1.1.1","1.0.0.1","2606:4700:4700::1111","2606:4700:4700::1001","8.8.8.8","8.8.4.4","2001:4860:4860::8888","2001:4860:4860::8844","9.9.9.9","149.112.112.112","2620:fe::fe","2620:fe::9"},names={"cloudflare-dns.com","dns.google","dns.quad9.net"};
  JSONArray rows=new JSONArray();rows.put(new JSONObject().put("id","selected").put("name","Selected DNS").put("kind","selected").put("address","10.77.0.53").put("port",5353).put("transport","udp").put("route","entry-wg").put("route_label","Selected DNS via entry-wg").put("samples",3).put("failed",0).put("ready",true).put("median_ms",7.25));
  for(int i=0;i<12;i++){JSONObject row=new JSONObject().put("id",ids[i]).put("name",ids[i]).put("kind","public").put("address",addresses[i]).put("port",transport.equals("tcp")?53:transport.equals("tls")?853:443).put("transport",transport).put("route","exit").put("route_label","Current Tor connection").put("samples",3).put("failed",0).put("ready",true).put("median_ms",10.5);if(!transport.equals("tcp"))row.put("server_name",names[i/4]);if(transport.equals("https"))row.put("path","/dns-query");rows.put(row);}
  return new JSONObject().put("schema",1).put("request_id",id).put("node_id","exit-owned").put("session_id","session-owned").put("public_transport",transport).put("stage","complete").put("complete",true).put("drained",true).put("results",rows);
 }
 static JSONObject validate(JSONObject value,String transport,boolean finished)throws Exception{return AndroidDNSMeasurementReceipt.validate(value.toString(),"a".repeat(32),"exit-owned","session-owned",transport,finished);}
 static void receipts()throws Exception{
  for(String transport:new String[]{"tcp","tls","https"}){JSONObject r=receipt("a".repeat(32),transport);validate(r,transport,true);String text=AndroidDNSMeasurementReceipt.render(r);check(text.contains("Complete DNS query time")&&text.contains("Selected DNS")&&text.contains("UDP")&&text.contains("10.77.0.53:5353")&&text.contains("7.3 ms"),"selected DNS route or complete-query meaning was lost");}
  for(String reason:new String[]{"request","node","session","transport","schema","typed-schema","typed-complete","typed-drained","not-drained","stage","top-failure","missing-row","duplicate","id","address","port","protocol","route","sni","path","samples","typed-samples","failed","typed-ready","median","typed-median","failure","selected-kind","selected-transport","name-control"}){
   JSONObject r=receipt("a".repeat(32),"https"),row=r.getJSONArray("results").getJSONObject(1);
   switch(reason){case "request":r.put("request_id","b".repeat(32));break;case "node":r.put("node_id","other");break;case "session":r.put("session_id","other");break;case "transport":r.put("public_transport","tcp");break;case "schema":r.put("schema",2);break;case "typed-schema":r.put("schema","1");break;case "typed-complete":r.put("complete","true");break;case "typed-drained":r.put("drained","true");break;case "not-drained":r.put("drained",false);break;case "stage":r.put("stage","idle");break;case "top-failure":r.put("failure","native retired");break;case "missing-row":r.put("results",new JSONArray());break;case "duplicate":row.put("id","selected");break;case "id":row.put("id","other");break;case "address":row.put("address","10.77.0.1");break;case "port":row.put("port",80);break;case "protocol":row.put("transport","udp");break;case "route":row.put("route","direct");break;case "sni":row.put("server_name","unowned.invalid");break;case "path":row.put("path","/other");break;case "samples":row.put("samples",2);break;case "typed-samples":row.put("samples","3");break;case "failed":row.put("failed",1);break;case "typed-ready":row.put("ready","true");break;case "median":row.put("median_ms",0);break;case "typed-median":row.put("median_ms","10.5");break;case "failure":row.put("failure","timeout");break;case "selected-kind":r.getJSONArray("results").getJSONObject(0).put("kind","public");break;case "selected-transport":r.getJSONArray("results").getJSONObject(0).put("transport","system");break;case "name-control":row.put("name","bad\nlabel");break;}
   reject(()->validate(r,"https",true));
  }
  for(int index:new int[]{0,1}){JSONObject wrongLabel=receipt("a".repeat(32),"https");wrongLabel.getJSONArray("results").getJSONObject(index).put("route_label","Uncaptured DNS route");reject(()->validate(wrongLabel,"https",true));}
  JSONObject r=receipt("a".repeat(32),"tcp"),failed=r.getJSONArray("results").getJSONObject(3);failed.put("ready",false).put("samples",0).put("failed",3).put("failure","IPv6 is disabled for this captured connection");failed.remove("median_ms");validate(r,"tcp",true);check(AndroidDNSMeasurementReceipt.render(r).contains("Unavailable"),"policy filtered resolver disappeared");failed.put("median_ms",1);reject(()->validate(r,"tcp",true));
 }
 static final class Callback implements AndroidNativeDNSMeasurement.Callback {
  final CountDownLatch finished=new CountDownLatch(1);volatile String result;volatile Throwable error;volatile int progresses;
  public void progress(String stage){progresses++;}public void finished(String r,Throwable e){result=r;error=e;finished.countDown();}
 }
 static void workers()throws Exception{
  for(String transport:new String[]{"tcp","tls","https"}){
   Libbox.dnsMeasurementReset();Fixture f=new Fixture(true,true);f.prove();RouterDNSMeasurement probe=f.create();LayeredVpnService s=live(f,probe);probe.response=()->{try{return receipt(probe.request,probe.transport).toString();}catch(Exception e){throw new RuntimeException(e);}};
   AtomicLong clock=new AtomicLong(10_000_000_000L);AndroidNativeDNSMeasurement worker=new AndroidNativeDNSMeasurement(clock::get);reject(worker::currentReceipt);Callback callback=new Callback();worker.run("exit-owned",transport,callback);check(callback.finished.await(3,TimeUnit.SECONDS),"DNS worker did not finish");check(callback.error==null&&callback.result!=null&&probe.starts==1&&probe.drains==1&&!worker.isRunning()&&!AndroidMTUMeasurementGate.held(),"DNS successful lifecycle lost owner or result");String old=probe.request;
   check(worker.currentReceipt().getString("request_id").equals(old),"completed request lost selectable current receipt");clock.addAndGet(119_000_000_000L);worker.currentReceipt();probe.onStatus=()->clock.addAndGet(1_000_000_000L);reject(worker::currentReceipt);probe.onStatus=null;reject(worker::currentReceipt);
   callback=new Callback();worker.run("exit-owned",transport,callback);check(callback.finished.await(3,TimeUnit.SECONDS)&&!old.equals(probe.request),"Retest reused request nonce");check(worker.currentReceipt().getString("request_id").equals(probe.request),"Retest did not renew expired selectable receipt");
   CountDownLatch cancelling=new CountDownLatch(1),cancelled=new CountDownLatch(1);Thread cancellation=new Thread(()->{cancelling.countDown();worker.cancel();cancelled.countDown();});
   synchronized(worker){cancellation.start();check(cancelling.await(1,TimeUnit.SECONDS),"cancellation not scheduled");long deadline=System.nanoTime()+1_000_000_000L;while(cancellation.getState()!=Thread.State.BLOCKED&&cancelled.getCount()!=0&&System.nanoTime()<deadline)Thread.yield();check(cancellation.getState()==Thread.State.BLOCKED&&cancelled.getCount()==1,"DNS cancellation escaped atomic result publication");}
   cancellation.join(1000);check(cancelled.getCount()==0,"DNS cancellation did not release its monitor");reject(worker::currentReceipt);
   callback=new Callback();worker.run("exit-owned",transport,callback);check(callback.finished.await(3,TimeUnit.SECONDS),"Retest after cancellation did not finish");((AtomicLong)field("lifecycle").get(s)).incrementAndGet();reject(worker::currentReceipt);s.onDestroy();
  }
  for(String reason:new String[]{"cancel","network","late-start","start-failed","bad-result"}){
   Libbox.dnsMeasurementReset();Fixture f=new Fixture(false,true);f.prove();RouterDNSMeasurement probe=f.create();LayeredVpnService s=live(f,probe);AtomicLong generation=(AtomicLong)field("lifecycle").get(s);
   CountDownLatch started=new CountDownLatch(1);probe.drainEntered=new CountDownLatch(1);probe.drainRelease=new CountDownLatch(1);probe.onStart=()->{started.countDown();if(reason.equals("late-start"))generation.incrementAndGet();};probe.failStart=reason.equals("start-failed");if(reason.equals("bad-result"))probe.response=()->"{}";
   AndroidNativeDNSMeasurement worker=new AndroidNativeDNSMeasurement();Callback callback=new Callback();worker.run("exit-owned","tcp",callback);
   if(!reason.equals("start-failed"))check(started.await(2,TimeUnit.SECONDS),"DNS Start not reached");
   if(reason.equals("cancel"))worker.cancel();if(reason.equals("network"))android.net.ConnectivityManager.networks=new android.net.Network[]{};
   check(probe.drainEntered.await(2,TimeUnit.SECONDS),"DNS native drain not attempted");check(worker.isRunning()&&AndroidMTUMeasurementGate.held()&&callback.finished.getCount()==1,"DNS cancellation released worker or MTU before drain");probe.drainRelease.countDown();
   check(callback.finished.await(3,TimeUnit.SECONDS)&&callback.error!=null&&callback.result==null&&!worker.isRunning()&&!AndroidMTUMeasurementGate.held()&&probe.cancels>0,"DNS invalidation adopted a stale receipt or leaked gate");s.onDestroy();
  }
 }
 public static void main(String[]args){try{exactAndRejected();lateFactory();serviceAdoption();requests();receipts();workers();System.out.println("Android DNS ownership/receipt/worker: "+checks+" checks");}catch(Throwable failed){failed.printStackTrace();System.exit(1);}}
}'''

def main():
 jar=Path(os.environ.get("ANDROID_JSON_JAR","/usr/share/java/com.android.json.jar"))
 if not jar.is_file() or not shutil.which("javac"):raise RuntimeError("JDK and Android JSON required")
 with tempfile.TemporaryDirectory(prefix="routervpn-native-dns-") as directory:
  root=Path(directory)
  for name,source in SOURCES.items():
   path=root/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_text(source)
  app=root/"com/eabusham/routervpn"
  for name in ("AndroidExternalSession","AndroidTorSession","AndroidNumericAddress","LayeredVpnService","AndroidNativeDNSMeasurement","AndroidDNSMeasurementReceipt","AndroidMTUMeasurementGate"):
   shutil.copyfile(JAVA/(name+".java"),app/(name+".java"))
  (app/"ExternalDNSMeasurementTest.java").write_text(HARNESS)
  compile_args=["javac","--release","17","-encoding","UTF-8","-proc:none","-cp",str(jar),"-d",str(root/"classes"),*map(str,root.rglob("*.java"))]
  run_args=["java","-cp",os.pathsep.join((str(root/"classes"),str(jar))),"com.eabusham.routervpn.ExternalDNSMeasurementTest"]
  subprocess.run(compile_args,check=True,timeout=45);subprocess.run(run_args,check=True,timeout=30)
  for name,old,new,label in (
   ("AndroidTorSession.java","dnsOwned = dnsOwned && request == proof && proved && !cancelled && current();","dnsOwned = true;","Tor late DNS factory"),
   ("AndroidExternalSession.java","dnsOwned = request == proof && healthy();","dnsOwned = true;","external late DNS factory"),
   ("LayeredVpnService.java","service.dnsMeasurement!=probe||","","exact retained DNS owner"),
   ("AndroidDNSMeasurementReceipt.java",'!session.equals(text(status,"session_id",128))||',"","DNS session receipt binding"),
   ("AndroidNativeDNSMeasurement.java","job.owner.drain();joined=true;","joined=true;","DNS worker drain hold"),
   ("AndroidNativeDNSMeasurement.java","return elapsed>=0&&elapsed<RESULT_LIFETIME_NS;","return true;","DNS receipt monotonic expiry"),
   ("AndroidNativeDNSMeasurement.java","void cancel(){final Job job;synchronized(this){completed=null;job=active;if(job!=null)job.cancelled=true;}if(job!=null)job.owner.cancel();}","void cancel(){completed=null;Job job=active;if(job==null)return;job.cancelled=true;job.owner.cancel();}","DNS atomic cancellation publication"),
  ):
   path=app/name;source=path.read_text();assert source.count(old)==1,label;path.write_text(source.replace(old,new))
   subprocess.run(compile_args,check=True,timeout=45)
   result=subprocess.run(run_args,capture_output=True,text=True,timeout=30)
   assert result.returncode!=0 and "AssertionError" in result.stderr,label+" negative control escaped"
   path.write_text(source)
  print("Android DNS negative controls: 7 rejected")

if __name__=="__main__":main()
