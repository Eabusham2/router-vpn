#!/usr/bin/env python3
"""Execute live-winner capture in the whole shipping Android VPN service."""
from pathlib import Path
import importlib.util
import os
import shutil
import subprocess
import tempfile

ROOT=Path(__file__).resolve().parents[1]
JAVA=ROOT/'android/app/src/main/java/com/eabusham/routervpn'
spec=importlib.util.spec_from_file_location('capture_service_types',ROOT/'android/test_android_layered_service_compile.py')
T=importlib.util.module_from_spec(spec);spec.loader.exec_module(T)
HARNESS=r'''package com.eabusham.routervpn;
import java.lang.reflect.*;import java.io.File;import java.util.*;import java.util.concurrent.atomic.AtomicLong;import io.nekohasekai.libbox.*;import org.json.*;
public final class MultihopRestoreTest {
 static int checks;static void check(boolean value,String message){checks++;if(!value)throw new AssertionError(message);}
 static Field field(String name)throws Exception{Field f=LayeredVpnService.class.getDeclaredField(name);f.setAccessible(true);return f;}
 static void set(LayeredVpnService service,String name,Object value)throws Exception{field(name).set(service,value);}
 static Object get(LayeredVpnService service,String name)throws Exception{return field(name).get(service);}
 static AndroidHomeStateStore.Snapshot home(){AndroidHomeStateStore.Snapshot s=new AndroidHomeStateStore.Snapshot();s.connected=true;s.pathGeneration=17;s.phase="connected";s.pathProof="passed";s.sessionId="captured-home";s.logicalMode="multihop";s.runtimeMode="max-quic-awg";s.activeEntryMode="reality-xhttp";s.activeEntryId="entry";s.activeExitId="exit";return s;}
 static String pins()throws Exception{return new JSONObject().put("expected_packet_public_key",java.util.Base64.getEncoder().encodeToString(new byte[]{1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32})).put("expected_pq_client_identity","ab".repeat(32)).toString();}
 static JSONObject progress(String selected)throws Exception{return new JSONObject().put("stage","selected").put("complete",true).put("execution",selected).put("measurements",new JSONArray());}
 static final class Fixture {
  final LayeredVpnService service=new LayeredVpnService();final RouterMultihop plan=new RouterMultihop();final android.net.ConnectivityManager connectivity=new android.net.ConnectivityManager();final JSONObject metadata;
  Fixture(String requested,String selected,boolean nativeOwner)throws Exception{
   AndroidHomeStateStore.value=home();AndroidHomeStateStore.emergency=false;set(service,"multihopHomeOwner",home());set(service,"currentService",new java.lang.ref.WeakReference<>(service));
   set(service,"state","UP");set(service,"activeConfig","captured-config");set(service,"activeSession",new File("captured-native-session"));set(service,"commandServer",new CommandServer(service,service));set(service,"executionProved",true);set(service,"hopMeasurement",new RouterHopMeasurement());set(service,"connectivity",connectivity);
   Method network=LayeredVpnService.class.getDeclaredMethod("executionNetworkIdentity");network.setAccessible(true);set(service,"executionNetwork",network.invoke(service));
   metadata=new JSONObject().put("execution",requested).put("entry_mode","reality-xhttp").put("exit_mode","max-quic-awg");metadata();plan.progress=progress(selected).toString();plan.pins=selected.equals("server")?pins():"{}";set(service,"executionController",nativeOwner?plan:null);
  }
  void metadata()throws Exception{set(service,"multihopMetadata",metadata.toString());}
  LayeredVpnService.CapturedMultihop receipt()throws Exception{return LayeredVpnService.capturedMultihop("captured-home");}
  String capture()throws Exception{return receipt().execution;}
 }
 interface Mutation{void change(Fixture fixture)throws Exception;}
 static void reject(String name,Mutation mutation)throws Exception{Fixture f=new Fixture("auto","server",true);mutation.change(f);boolean rejected=false;try{f.capture();}catch(Exception expected){rejected=true;}check(rejected,"stale or invalid native winner accepted: "+name);}
 public static void main(String[] args)throws Exception{
  for(String policy:new String[]{"local","server","auto"})for(String selected:new String[]{"local","server"}){
   if(!policy.equals("auto")&&!policy.equals(selected))continue;Fixture f=new Fixture(policy,selected,true);check(f.capture().equals(selected),"valid selected route changed");check(f.metadata.getString("execution").equals(policy),"capture changed saved requested choice");check(f.plan.runs==0,"capture reran comparison or fabricated a fresh proof");check(f.receipt().serverIdentityPins.equals(f.plan.pins),"captured pins lost their exact winner");check(f.receipt().matchesHome(AndroidHomeStateStore.value),"receipt lost home identity");check(f.receipt().sameOwner(f.receipt()),"same owned capture changed");
  }
  Fixture local=new Fixture("local","local",false);check(local.capture().equals("local"),"proved direct local graph lost restoration");
  Map<String,Mutation> mutations=new LinkedHashMap<>();
  mutations.put("stopped",f->set(f.service,"explicitStop",true));mutations.put("not-UP",f->set(f.service,"state","STOPPING"));mutations.put("native-proof",f->set(f.service,"executionProved",false));
  mutations.put("missing-command-server",f->set(f.service,"commandServer",null));mutations.put("missing-native-session",f->set(f.service,"activeSession",null));mutations.put("missing-private-proof-owner",f->set(f.service,"hopMeasurement",null));mutations.put("missing-captured-home",f->set(f.service,"multihopHomeOwner",null));
  mutations.put("emergency",f->AndroidHomeStateStore.emergency=true);mutations.put("session",f->AndroidHomeStateStore.value.sessionId="new-session");mutations.put("generation",f->AndroidHomeStateStore.value.pathGeneration++);
  mutations.put("entry",f->AndroidHomeStateStore.value.activeEntryId="another");mutations.put("exit",f->AndroidHomeStateStore.value.activeExitId="another");mutations.put("entry-mode",f->AndroidHomeStateStore.value.activeEntryMode="wg");mutations.put("exit-mode",f->AndroidHomeStateStore.value.runtimeMode="shadowsocks");
  mutations.put("disconnected",f->AndroidHomeStateStore.value.connected=false);mutations.put("home-proof",f->AndroidHomeStateStore.value.pathProof="pending");mutations.put("home-phase",f->AndroidHomeStateStore.value.phase="connecting");mutations.put("wrong-topology",f->AndroidHomeStateStore.value.logicalMode="external");
  mutations.put("network",f->f.connectivity.network=new android.net.Network());mutations.put("missing-network",f->set(f.service,"executionNetwork",""));mutations.put("empty-network",f->set(f.service,"executionNetwork","[]"));
  mutations.put("metadata",f->set(f.service,"multihopMetadata",null));mutations.put("metadata-mode",f->{f.metadata.put("entry_mode","wg");f.metadata();});mutations.put("contradictory-winner",f->{f.metadata.put("execution","local");f.metadata();});
  mutations.put("missing-comparison",f->set(f.service,"executionController",null));mutations.put("unhealthy-lease",f->f.plan.alive=false);mutations.put("incomplete",f->f.plan.progress=progress("server").put("complete",false).toString());mutations.put("failed",f->f.plan.progress=progress("server").put("failure","expired").toString());mutations.put("comparing",f->f.plan.progress=progress("server").put("stage","comparing").toString());mutations.put("invalid-selected",f->f.plan.progress=progress("auto").toString());mutations.put("oversized",f->f.plan.progress=" ".repeat(65537));
  mutations.put("changed-after-native-read",f->f.plan.onProgress=()->AndroidHomeStateStore.value=homeWithNewGeneration());
  mutations.put("stop-after-native-read",f->f.plan.onProgress=()->{try{set(f.service,"explicitStop",true);}catch(Exception e){throw new AssertionError(e);}});
  mutations.put("lifecycle-after-native-read",f->f.plan.onProgress=()->{try{((AtomicLong)get(f.service,"lifecycle")).incrementAndGet();}catch(Exception e){throw new AssertionError(e);}});
  mutations.put("replacement-after-native-read",f->f.plan.onProgress=()->{try{set(f.service,"currentService",new java.lang.ref.WeakReference<>(new LayeredVpnService()));}catch(Exception e){throw new AssertionError(e);}});
  mutations.put("missing-server-pins",f->f.plan.pins="{}");mutations.put("wrong-packet-key",f->f.plan.pins=new JSONObject(pins()).put("expected_packet_public_key","bad").toString());mutations.put("null-pq-pin",f->f.plan.pins=new JSONObject(pins()).put("expected_pq_client_identity",JSONObject.NULL).toString());mutations.put("unknown-pin",f->f.plan.pins=new JSONObject(pins()).put("extra","unowned").toString());
  mutations.put("native-pin-error",f->f.plan.pinFailure=true);mutations.put("owner-during-pins",f->f.plan.onPins=()->AndroidHomeStateStore.value=homeWithNewGeneration());
  mutations.put("config-during-pins",f->f.plan.onPins=()->{try{set(f.service,"activeConfig","replacement");}catch(Exception e){throw new AssertionError(e);}});
  mutations.put("session-during-pins",f->f.plan.onPins=()->{try{set(f.service,"activeSession",new File("replacement"));}catch(Exception e){throw new AssertionError(e);}});
  mutations.put("home-mode-during-pins",f->f.plan.onPins=()->{AndroidHomeStateStore.Snapshot changed=home();changed.runtimeMode="wg-pq";AndroidHomeStateStore.value=changed;});
  mutations.put("native-health-during-pins",f->f.plan.onPins=()->f.plan.alive=false);
  for(var mutation:mutations.entrySet())reject(mutation.getKey(),mutation.getValue());
  System.out.println("Android native multihop winner capture: "+checks+" whole-service checks; retained Box/lease/Home/network ownership and no score reuse");
 }
 static AndroidHomeStateStore.Snapshot homeWithNewGeneration(){AndroidHomeStateStore.Snapshot s=home();s.pathGeneration++;return s;}
}
'''

def main():
    jar=Path(os.environ.get('ANDROID_JSON_JAR','/usr/share/java/com.android.json.jar'))
    if not jar.is_file():raise RuntimeError('Actual Android JSON library required')
    stubs=dict(T.STUBS);stubs.pop('org/json/JSONObject.java')
    stubs['android/net/ConnectivityManager.java']='''package android.net;public class ConnectivityManager {
 public Network network=new Network();public Network[] getAllNetworks(){return new Network[]{network};}public Network getActiveNetwork(){return network;}public NetworkCapabilities getNetworkCapabilities(Network n){return new NetworkCapabilities();}public LinkProperties getLinkProperties(Network n){return new LinkProperties();}
 public int getConnectionOwnerUid(int p,java.net.InetSocketAddress a,java.net.InetSocketAddress b){return 1;}public void registerDefaultNetworkCallback(NetworkCallback c){}public void unregisterNetworkCallback(NetworkCallback c){}
 public static class NetworkCallback{public void onAvailable(Network n){}public void onLost(Network n){}public void onCapabilitiesChanged(Network n,NetworkCapabilities c){}public void onLinkPropertiesChanged(Network n,LinkProperties p){}}
}'''
    stubs['io/nekohasekai/libbox/RouterMultihop.java']='''package io.nekohasekai.libbox;public class RouterMultihop {public boolean alive=true;public String progress,pins="{}";public boolean pinFailure;public int runs;public Runnable onProgress,onPins;public void networkChanged(){}public boolean healthy(){return alive;}public String progressJSON(){if(onProgress!=null)onProgress.run();return progress;}public String serverIdentityPinsJSON()throws Exception{if(onPins!=null)onPins.run();if(pinFailure)throw new IllegalStateException("stale pins");return pins;}public String config(){return "";}public void run(CommandServer c)throws Exception{runs++;}public void close()throws Exception{}}'''
    controller=(JAVA/'AndroidMultihopController.java').read_text()
    validator=controller[controller.index('    static String validatedServerIdentityPins('):controller.index('    private static void applyServerIdentityPins(')]
    stubs['com/eabusham/routervpn/AndroidMultihopController.java']='package com.eabusham.routervpn;import org.json.*;import android.util.Base64;final class AndroidMultihopController{'+validator+'}'
    # Retain the shared native SessionInfo boundary used by the whole service.
    native=stubs['com/eabusham/routervpn/NativeSingBoxController.java']
    stubs['com/eabusham/routervpn/NativeSingBoxController.java']=native[:-1]+'static boolean nativeWireGuardFamily(String m){return java.util.Arrays.asList("wg","awg2-fast","awg2-strong").contains(m);}static boolean nativePQFamily(String m){return java.util.Arrays.asList("wg-pq","awg2-pq").contains(m);}}'
    stubs['com/eabusham/routervpn/AndroidNativeMAXProfile.java']='package com.eabusham.routervpn;final class AndroidNativeMAXProfile{static boolean isMode(String m){return java.util.Arrays.asList("max-tls-wg","max-quic-wg","max-tls-awg","max-quic-awg").contains(m);}}'
    stubs['android/util/Base64.java']='package android.util;public class Base64{public static final int DEFAULT=0,NO_WRAP=2;public static byte[] decode(String s,int flags){return java.util.Base64.getMimeDecoder().decode(s);}public static String encodeToString(byte[] b,int flags){return java.util.Base64.getEncoder().encodeToString(b);}}'
    with tempfile.TemporaryDirectory(prefix='routervpn-multihop-restore-') as directory:
        root=Path(directory)
        for name,body in stubs.items():p=root/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_text(body)
        app=root/'com/eabusham/routervpn';target=app/'LayeredVpnService.java';target.write_text((JAVA/'LayeredVpnService.java').read_text());(app/'MultihopRestoreTest.java').write_text(HARNESS)
        compile=['javac','--release','17','-encoding','UTF-8','-proc:none','-cp',str(jar),'-d',str(root/'classes'),*map(str,root.rglob('*.java'))]
        run=['java','-cp',os.pathsep.join((str(root/'classes'),str(jar))),'com.eabusham.routervpn.MultihopRestoreTest']
        subprocess.run(compile,check=True,timeout=45);subprocess.run(run,check=True,timeout=30)
        source=target.read_text();controls=(('owner.pathGeneration!=home.pathGeneration','false','Home generation'),('||!plan.healthy()','||false','lease health'),('!progress.optBoolean("complete",false)','false','native completion'),('generation!=service.lifecycle.get()','false','native lifecycle'))
        for old,new,label in controls:
            # Scope mutations to the new capture helper, preserving other lifecycle gates.
            start=source.index('    static String capturedMultihopExecution(');end=source.index('    static String hopMeasurementRequest(',start);section=source[start:end]
            assert section.count(old)==1,label;changed=section.replace(old,new)
            if label=='lease health':changed=changed.replace('plan!=null&&!plan.healthy()','false')
            target.write_text(source[:start]+changed+source[end:]);subprocess.run(compile,check=True,timeout=45,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            rejected=subprocess.run(run,capture_output=True,text=True,timeout=30)
            if rejected.returncode==0 or 'AssertionError' not in rejected.stderr:raise AssertionError(label+' negative control escaped')
            target.write_text(source)
        print('Android retained multihop winner: four ownership negative controls rejected')

if __name__=='__main__':main()
