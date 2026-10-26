#!/usr/bin/env python3
"""Execute Android's retained external proof, real MTU adapter and result view.

Only OS handles and the native constructor boundary are doubled. The native
factory/transport/readback engine has separate pinned traffic and binding gates.
"""
from pathlib import Path
import importlib.util
import os
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
JAVA = ROOT / "android/app/src/main/java/com/eabusham/routervpn"


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


M = load("tor_mtu_platform", "android/test_android_mtu_session.py")
E = load("tor_mtu_proof", "android/test_android_tor_session.py")
T = load("tor_mtu_widgets", "android/test_android_tor_form.py")
SOURCES = dict(T.UI)
SOURCES.update(M.STUBS)

SOURCES["android/os/Handler.java"] = "package android.os;public class Handler {public Handler(Looper value){}public void removeCallbacks(Runnable work){}public boolean postDelayed(Runnable work,long delay){return true;}}"
SOURCES["android/os/Looper.java"] = "package android.os;public class Looper {public static Looper getMainLooper(){return new Looper();}}"
SOURCES["android/app/AlertDialog.java"] = SOURCES["android/app/AlertDialog.java"].replace("BUTTON_NEGATIVE=-2;", "BUTTON_NEGATIVE=-2,BUTTON_NEUTRAL=-3;").replace("public AlertDialog create(){", "public Builder setNeutralButton(CharSequence text,OnClickListener listener){return button(BUTTON_NEUTRAL,text,listener);}public AlertDialog create(){")
SOURCES["android/widget/TextView.java"] = SOURCES["android/widget/TextView.java"][:-1] + "public void setTextIsSelectable(boolean value){} }"
SOURCES["io/nekohasekai/libbox/RouterHopMeasurement.java"] = "package io.nekohasekai.libbox;public class RouterHopMeasurement {public void close(){}}"
SOURCES.pop("com/eabusham/routervpn/AndroidTorSession.java")
SOURCES["com/eabusham/routervpn/AndroidTorProfile.java"] = E.SOURCES["com/eabusham/routervpn/AndroidTorProfile.java"]
SOURCES["io/nekohasekai/libbox/RouterTorProofRequest.java"] = E.SOURCES["io/nekohasekai/libbox/RouterTorProofRequest.java"]
SOURCES["io/nekohasekai/libbox/RouterDNSMeasurement.java"] = E.SOURCES["io/nekohasekai/libbox/RouterDNSMeasurement.java"]
SOURCES["io/nekohasekai/libbox/Libbox.java"] = SOURCES["io/nekohasekai/libbox/Libbox.java"][:-1] + r'''
 public static volatile RouterTorProofRequest torCreated;
 public static volatile java.util.concurrent.CountDownLatch dnsRelease;
 public static CommandServer passedServer;public static RouterTorProofRequest passedProof;
 public static String passedSource,passedCapture;public static int externalCalls;
 public static RouterTorProofRequest routerTorCreateProof(CommandServer core,String tag,String session){torCreated=new RouterTorProofRequest(core,session,"");return torCreated;}
 public static RouterTorProofRequest routerTorCreateProofWithPredecessor(CommandServer core,String tag,String session,String predecessor){torCreated=new RouterTorProofRequest(core,session,predecessor);return torCreated;}
 public static void routerStrategyDNSProof(CommandServer core)throws Exception{if(torCreated.server!=core||!torCreated.healthy())throw new IllegalStateException("wrong native Tor owner");}
 public static RouterHopMeasurement routerTorCreateHopMeasurement(CommandServer core,RouterTorProofRequest proof,String external){return new RouterHopMeasurement();}
 public static RouterDNSMeasurement routerTorCreateDNSMeasurement(CommandServer core,RouterTorProofRequest proof,String external){return new RouterDNSMeasurement();}
 public static RouterMTU newRouterTorMTU(CommandServer core,RouterMTUPlatform platform,RouterTorProofRequest proof,String source,String capture)throws Exception{
  if(proof==null||!proof.healthy()||proof.server!=core)throw new IllegalStateException("wrong retained Tor proof/config");
  passedServer=core;passedProof=proof;passedSource=source;passedCapture=capture;externalCalls++;
  RouterMTU value=newRouterMTU(core,platform,source,capture);
  org.json.JSONObject exit=new org.json.JSONObject(capture),entry=proof.predecessor.isEmpty()?new org.json.JSONObject():new org.json.JSONObject(proof.predecessor);
  String exitMode=exit.optString("mtu_policy","default"),entryMode=entry.optString("mtu_policy","default");
  value.automatic="auto".equals(exitMode)&&!exit.optBoolean("jumbo_tun",false)&&!entry.optBoolean("jumbo_tun",false)&&!"fixed".equals(entryMode)&&!"manual".equals(entryMode);
  return value;
 }
}'''
SOURCES["com/eabusham/routervpn/LayeredVpnService.java"] = r'''package com.eabusham.routervpn;
final class LayeredVpnService {static String response;static String mtuRequest(String operation,String session,String request)throws Exception{return response;}}'''

HARNESS = r'''package com.eabusham.routervpn;
import org.json.*;import io.nekohasekai.libbox.*;import java.util.concurrent.*;import java.util.concurrent.atomic.*;import java.lang.reflect.*;import android.app.*;import android.widget.*;
public final class TorMTUTest {
 static int checks;interface Operation{void run()throws Exception;}
 static void check(boolean value,String message){checks++;if(!value)throw new AssertionError(message);}
 static void reject(Operation action,String message)throws Exception{try{action.run();}catch(Exception expected){checks++;return;}throw new AssertionError(message);}
 static final class Fixture implements AndroidTorSession.Owner {
  final Main.Fixture mtu=new Main.Fixture();final CommandServer server=new CommandServer();volatile CommandServer currentServer=server;
  volatile String network="physical-owned";AndroidTorSession external;final String source="exact-complete-config",capture;
  Fixture(String policy,boolean entry)throws Exception{this(policy,entry,false,"auto",false,1280);}
  Fixture(String policy,boolean entry,boolean jumbo,String entryPolicy,boolean entryJumbo,int capacity)throws Exception{
   mtu.establish(capacity);JSONObject p=new JSONObject().put("id","exit-owned").put("mtu_policy",policy).put("dns_mode","custom").put("dns_protocol","doh").put("dns_host","resolver.example").put("jumbo_tun",jumbo);
   if("fixed".equals(policy)||"manual".equals(policy))p.put("manual_mtu",capacity);
   capture=p.toString();JSONObject metadata=new JSONObject().put("session_id","session-owned").put("external_id","exit-owned").put("tor_profile",p);
   if(entry){JSONObject predecessor=new JSONObject().put("id","entry-owned").put("api_token","captured-entry-token").put("mtu_policy",entryPolicy).put("jumbo_tun",entryJumbo);if("fixed".equals(entryPolicy)||"manual".equals(entryPolicy))predecessor.put("manual_mtu",capacity);metadata.put("predecessor_profile",predecessor);}
   external=new AndroidTorSession(metadata,source,server,this);
  }
  public boolean current(AndroidTorSession value,CommandServer core){return value==external&&core==currentServer;}
  public String network(){return network;}
  void prove()throws Exception{external.prove();}
 }
 static void successful()throws Exception{
  for(boolean entry:new boolean[]{false,true}){
   Fixture f=new Fixture("auto",entry);reject(()->f.external.newMTU(f.mtu.owner),"unproved external owner constructed MTU");f.prove();RouterTorProofRequest proof=Libbox.torCreated;
   JSONObject mutable=f.external.mtuProfile();mutable.put("mtu_policy","fixed").put("dns_host","8.8.8.8");
   int calls=Libbox.externalCalls;f.mtu.owner.activateTor(f.external);RouterMTU nativeOwner=Libbox.latest;
   check(Libbox.externalCalls==calls+1&&nativeOwner.starts==1,"proved Auto external did not start exactly once");
   check(Libbox.passedServer==f.server&&Libbox.passedProof==proof&&f.source.equals(Libbox.passedSource)&&f.capture.equals(Libbox.passedCapture),"MTU lost exact native proof/source/DNS capture");
   check(f.mtu.owner.captureMTU().getMTU()==1280,"saved MTU history replaced actual OS readback");
   f.mtu.owner.activateTor(f.external);check(nativeOwner.starts==1,"duplicate automatic MTU constructor");
   Object hold=AndroidMTUMeasurementGate.acquire();f.mtu.owner.drainForMeasurement();check(!nativeOwner.running()&&nativeOwner.cancels==1,"Speed Lab did not drain external Auto-MTU");
   reject(()->f.mtu.owner.request("start",f.mtu.owner.identity,"a".repeat(32)),"Retest bypassed measurement hold");AndroidMTUMeasurementGate.release(hold);
   reject(()->f.mtu.owner.request("start","wrong-session","b".repeat(32)),"wrong session retested external path");
   f.mtu.owner.request("start",f.mtu.owner.identity,"c".repeat(32));f.mtu.owner.request("cancel",f.mtu.owner.identity,"c".repeat(32));check(nativeOwner.starts==2&&nativeOwner.cancels==2,"external Retest/Cancel did not retain owned controller");
   f.mtu.owner.close();check(nativeOwner.closes==1,"Tor MTU native owner was not closed");
  }
 }
 static void restrictions()throws Exception{
  for(String mode:new String[]{"fixed","manual","default"}){Fixture f=new Fixture(mode,false);f.prove();int calls=Libbox.externalCalls;f.mtu.owner.activateTor(f.external);check(Libbox.externalCalls==calls+1&&Libbox.latest.starts==0&&!Libbox.latest.autoRequested(),"configured external policy lost native readback or started Auto-MTU: "+mode);f.mtu.owner.close();}
  Fixture held=new Fixture("auto",false);held.prove();Object lease=AndroidMTUMeasurementGate.acquire();held.mtu.owner.activateTor(held.external);check(Libbox.latest.starts==0,"external automatic MTU ignored startup measurement hold");held.mtu.owner.drainForMeasurement();AndroidMTUMeasurementGate.release(lease);held.mtu.owner.activateTor(held.external);check(Libbox.latest.starts==1,"restored automatic MTU did not resume after measurement drain");held.mtu.owner.activateTor(held.external);check(Libbox.latest.starts==1,"restored automatic MTU restarted twice");held.mtu.owner.close();
  Fixture unreadable=new Fixture("auto",false);unreadable.prove();unreadable.mtu.mtu=1400;RouterMTU previous=Libbox.latest;int calls=Libbox.externalCalls;unreadable.mtu.owner.activateTor(unreadable.external);check(Libbox.externalCalls==calls+1&&Libbox.latest==previous,"failed OS readback created an unverified owner");unreadable.mtu.owner.close();
  for(String stale:new String[]{"cancel","server","network"}){Fixture f=new Fixture("auto",true);f.prove();calls=Libbox.externalCalls;if(stale.equals("cancel"))f.external.cancel();if(stale.equals("server"))f.currentServer=new CommandServer();if(stale.equals("network"))f.network="new-network";f.mtu.owner.activateTor(f.external);check(Libbox.externalCalls==calls,"stale external proof reached native constructor: "+stale);f.mtu.owner.close();}
 }
 static void configuredCapacity()throws Exception{
  for(String kind:new String[]{"direct-jumbo","default-jumbo","exit-fixed","entry-jumbo","entry-fixed"}){
   boolean inherited=kind.startsWith("entry-");String mode=kind.equals("default-jumbo")?"default":kind.equals("exit-fixed")?"fixed":"auto";
   Fixture f=new Fixture(mode,inherited,!inherited&&!kind.equals("exit-fixed"),kind.equals("entry-fixed")?"fixed":"auto",kind.equals("entry-jumbo"),9000);f.prove();f.mtu.owner.activateTor(f.external);RouterMTU nativeOwner=Libbox.latest;
   check(nativeOwner.starts==0&&nativeOwner.attempts==0&&!nativeOwner.autoRequested()&&nativeOwner.effectiveMTU==9000,"configured capacity became an optimizer candidate: "+kind);
   check(f.capture.equals(Libbox.passedCapture)&&new JSONObject(Libbox.passedCapture).getString("mtu_policy").equals(mode),"inherited capacity rewrote saved exit choice: "+kind);
   JSONObject status=new JSONObject(f.mtu.owner.request("status",f.mtu.owner.identity,""));
   check(!status.getBoolean("optimization_allowed")&&status.getBoolean("tor_connection")&&status.getInt("effective_mtu")==9000&&!status.getBoolean("measured")&&status.getString("source").equals("configured-unmeasured"),"configured capacity was labelled as a measured path: "+kind);
   reject(()->f.mtu.owner.request("start",f.mtu.owner.identity,"d".repeat(32)),"configured capacity admitted Retest: "+kind);
   f.mtu.owner.activateTor(f.external);check(nativeOwner.starts==0,"repeat activation forgot inherited authority: "+kind);
   f.mtu.owner.networkChanged();check(f.mtu.owner.captureMTU()==null,"retired capacity retained readback: "+kind);f.mtu.owner.close();check(nativeOwner.closes==1,"configured capacity lost native drain ownership: "+kind);
  }
  for(boolean inherited:new boolean[]{false,true}){
   Fixture f=new Fixture("auto",inherited,!inherited,"fixed",false,9000);f.prove();f.mtu.mtu=1500;RouterMTU prior=Libbox.latest;f.mtu.owner.activateTor(f.external);
   check(f.mtu.aborts==1&&f.mtu.owner.captureMTU()==null&&Libbox.latest==prior,"wrong large-capacity readback retained a connected owner");
   check(new JSONObject(f.mtu.owner.request("status",f.mtu.owner.identity,"")).getBoolean("optimization_allowed")==false,"failed capacity exposed Retest");f.mtu.owner.close();
  }
 }
 static void constructorOwnership()throws Exception{
  for(String stale:new String[]{"cancel","stop","server","network"}){
   Fixture f=new Fixture("auto",true);f.prove();Libbox.afterCreate=value->{value.closeFailures=1;if(stale.equals("cancel"))f.external.cancel();if(stale.equals("stop"))f.mtu.owner.networkChanged();if(stale.equals("server"))f.currentServer=new CommandServer();if(stale.equals("network"))f.network="replacement";};
   try{f.mtu.owner.activateTor(f.external);}finally{Libbox.afterCreate=null;}
   RouterMTU value=Libbox.latest;check(value.starts==0&&value.closes==1,"late native constructor was started after "+stale);f.mtu.owner.close();check(value.closes==2,"failed native drain lost sole Tor MTU handle after "+stale);f.mtu.owner.close();check(value.closes==2,"closed MTU handle was reused");
  }
  Fixture f=new Fixture("auto",true);f.prove();CountDownLatch entered=new CountDownLatch(1),release=new CountDownLatch(1),stopped=new CountDownLatch(1);AtomicReference<Throwable> failure=new AtomicReference<>();
  Libbox.afterCreate=value->{entered.countDown();if(!release.await(3,TimeUnit.SECONDS))throw new AssertionError("factory not released");};
  Thread start=new Thread(()->f.mtu.owner.activateTor(f.external));start.start();check(entered.await(2,TimeUnit.SECONDS),"external constructor not reached");
  Thread stop=new Thread(()->{try{f.mtu.owner.close();}catch(Throwable e){failure.set(e);}finally{stopped.countDown();}});stop.start();
  long end=System.nanoTime()+1_000_000_000L;while(f.mtu.owner.captureMTU()!=null&&System.nanoTime()<end)Thread.sleep(1);
  check(f.mtu.owner.captureMTU()==null&&stopped.getCount()==1,"Stop returned before external native constructor joined");release.countDown();start.join(2000);stop.join(2000);Libbox.afterCreate=null;
  check(!start.isAlive()&&!stop.isAlive()&&failure.get()==null&&Libbox.latest.starts==0&&Libbox.latest.closes==1,"external constructor escaped Stop ownership");
 }
 static JSONObject status(boolean publicPath)throws Exception{
  JSONObject transfer=new JSONObject().put("bytes",262144).put("seconds",0.25).put("mbps",8.388608);
  JSONObject row=new JSONObject().put("mtu",1420).put("working",true).put("median_rtt_ms",9.3).put("download",transfer).put("upload",new JSONObject(transfer.toString()));
  if(publicPath)row.put("latency_kind","https-response").put("packets_sent",0).put("packets_received",0).put("datagram_bytes",0);else row.put("packets_sent",6).put("packets_received",6).put("datagram_bytes",1392);
  return new JSONObject().put("request_id","a".repeat(32)).put("phase","complete").put("running",false).put("complete",true).put("measured",true).put("effective_mtu",1420).put("original_mtu",1280).put("source",publicPath?"measured-tor-system-tun-transfer":"measured-private-system-tun").put("candidates",new JSONArray().put(row));
 }
 static AlertDialog renderedDialog;
 static String render(JSONObject value)throws Exception{
  Constructor<AndroidMTUDialog> create=AndroidMTUDialog.class.getDeclaredConstructor(Activity.class);create.setAccessible(true);AndroidMTUDialog d=create.newInstance(new Activity());
  Field dialog=AndroidMTUDialog.class.getDeclaredField("dialog"),text=AndroidMTUDialog.class.getDeclaredField("text");dialog.setAccessible(true);text.setAccessible(true);
  renderedDialog=new AlertDialog.Builder(new Activity()).setPositiveButton("Retest",null).setNeutralButton("Cancel test",null).create();dialog.set(d,renderedDialog);TextView output=new TextView(new Activity());text.set(d,output);Method render=AndroidMTUDialog.class.getDeclaredMethod("render",JSONObject.class);render.setAccessible(true);render.invoke(d,value);return output.getText().toString();
 }
 static void display()throws Exception{
  for(boolean publicPath:new boolean[]{false,true}){
   String valid=render(status(publicPath));check(valid.contains("Verified current MTU: 1420")&&valid.contains("8.4↓ / 8.4↑ Mbps"),"valid MTU evidence not displayed");
   check(publicPath?valid.contains("Tor HTTPS transfer test")&&valid.contains("does not establish an unfragmented UDP packet limit")&&!valid.contains("Authenticated packets"):valid.contains("authenticated packet test"),"MTU evidence changed its measurement kind");
   for(String field:new String[]{"source","measured","complete","running","effective_mtu","working","bytes","seconds","mbps","median_rtt_ms","kind","packets","datagram","oversized"}){
    JSONObject invalid=status(publicPath),row=invalid.getJSONArray("candidates").getJSONObject(0);
    switch(field){case "source":invalid.put("source",publicPath?"measured-private-system-tun":"measured-tor-system-tun-transfer");break;case "measured":case "complete":invalid.put(field,false);break;case "running":invalid.put(field,true);break;case "effective_mtu":invalid.put(field,1280);break;case "working":row.put(field,false);break;case "bytes":row.getJSONObject("download").put(field,262143);break;case "seconds":row.getJSONObject("upload").put(field,0);break;case "mbps":row.getJSONObject("upload").put(field,99);break;case "median_rtt_ms":row.put(field,publicPath?0:-1);break;case "kind":row.put("latency_kind",publicPath?"icmp":"https-response");break;case "packets":row.put("packets_received",publicPath?6:5);break;case "datagram":row.put("datagram_bytes",publicPath?1392:0);break;case "oversized":for(int i=0;i<5;i++)invalid.getJSONArray("candidates").put(row);break;}
    check(!render(invalid).contains("Verified current MTU:"),"invalid/stale evidence advertised current: "+publicPath+" "+field);
   }
  }
  JSONObject jumbo=new JSONObject().put("phase","idle").put("source","configured-unmeasured").put("effective_mtu",9000).put("tor_connection",true).put("optimization_allowed",false).put("policy_note","Configured capacity; Auto MTU and Retest are disabled.");
  String configured=render(jumbo);check(configured.contains("9000 (configured, unmeasured)")&&!configured.contains("Verified current MTU:")&&configured.contains("Tor uses TCP streams")&&configured.contains("Auto MTU and Retest are disabled"),"Jumbo capacity was hidden or mislabelled");check(!renderedDialog.getButton(AlertDialog.BUTTON_POSITIVE).isEnabled(),"configured capacity enabled Retest");
 }
 public static void main(String[] args)throws Exception{successful();restrictions();configuredCapacity();constructorOwnership();display();System.out.println("Android Tor MTU: "+checks+" shipping-Java proof, readback, lifecycle, Retest/Cancel and renderer checks");}
}'''


def main():
    jar = Path(os.environ.get("ANDROID_JSON_JAR", "/usr/share/java/com.android.json.jar"))
    if not jar.is_file() or not shutil.which("javac"):
        raise RuntimeError("JDK and Android JSON are required for actual Tor MTU host checks")
    with tempfile.TemporaryDirectory(prefix="routervpn-external-mtu-") as directory:
        root = Path(directory)
        for name, source in SOURCES.items():
            target = root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(source)
        app = root / "com/eabusham/routervpn"
        (app / "Main.java").write_text(M.HARNESS)
        (app / "TorMTUTest.java").write_text(HARNESS)
        for name in ("AndroidMTUSession", "AndroidMTUMeasurementGate", "AndroidTorSession", "AndroidNumericAddress", "AndroidMTUDialog"):
            shutil.copyfile(JAVA / (name + ".java"), app / (name + ".java"))
        compile_args = ["javac", "--release", "17", "-encoding", "UTF-8", "-cp", str(jar), "-d", str(root / "classes"), *map(str, root.rglob("*.java"))]
        run_args = ["java", "-cp", os.pathsep.join((str(root / "classes"), str(jar))), "com.eabusham.routervpn.TorMTUTest"]
        subprocess.run(compile_args, check=True, timeout=45)
        subprocess.run(run_args, check=True, timeout=25)
        for name, before, after, label in (
            ("AndroidMTUSession.java", "if (closed || invalid || !tor.healthy()) { closeController(); return; }", "", "external constructor completion ownership"),
            ("AndroidMTUSession.java", "controller = created;\n                if (closed || invalid || !tor.healthy())", "if (closed || invalid || !tor.healthy())", "sole native owner adoption"),
            ("AndroidMTUSession.java", "if (!created.autoRequested())", "if (false)", "retained inherited capacity authority"),
            ("AndroidMTUSession.java", "if (large && !closed && !invalid) abortMTU", "if (false) abortMTU", "failed configured capacity abort"),
            ("AndroidTorSession.java", "Libbox.newRouterTorMTU(server, platform, proof, config, profile)", 'Libbox.newRouterTorMTU(server, platform, proof, config, "{}")', "immutable captured DNS/profile"),
            ("AndroidMTUDialog.java", '&& "https-response".equals(row.optString("latency_kind", ""))\n                && row.optInt', "&& true\n                && row.optInt", "public measurement kind"),
        ):
            path = app / name
            original = path.read_text()
            if original.count(before) != 1:
                raise AssertionError("Missing unique negative-control boundary: " + label)
            path.write_text(original.replace(before, after))
            subprocess.run(compile_args, check=True, timeout=45)
            result = subprocess.run(run_args, capture_output=True, text=True, timeout=20)
            if result.returncode == 0 or "AssertionError" not in result.stderr:
                raise AssertionError("Negative control escaped: " + label + "\n" + result.stderr)
            path.write_text(original)
        print("Android Tor MTU negative controls: 6 rejected")


if __name__ == "__main__":
    main()
