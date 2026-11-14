#!/usr/bin/env python3
"""Execute the shipping external cohort, native50 transaction and final adoption.

The coordinator, Speed Lab/controller, private stores, usage recorder, policy
and native-measurement wrapper are unchanged production Java. Android network
callbacks and encrypted-engine proof/traffic are explicit controlled boundaries.
Actual HTTPS exchanges and platform/native proof have separate executable gates.
"""
from pathlib import Path
import importlib.util
import os
import subprocess
import tempfile

ROOT=Path(__file__).resolve().parents[1]
JAVA=ROOT/'android/app/src/main/java/com/eabusham/routervpn'

def module(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value

E=module('comparison_statistics',ROOT/'android/test_android_external_node_statistics.py')
U=E.U
R=module('comparison_restoration',ROOT/'android/test_android_speed_lab_restore.py')

NETWORK={
'android/net/Network.java':'''package android.net;public final class Network {public final int id;public Network(int id){this.id=id;}public String toString(){return Integer.toString(id);}public boolean equals(Object o){return o instanceof Network&&((Network)o).id==id;}public int hashCode(){return id;}}''',
 'android/net/LinkProperties.java':'''package android.net;public final class LinkProperties implements android.os.Parcelable {public String name="eth0",address="192.0.2.3/24",dns="192.0.2.1",routes="0.0.0.0/0";public int mtu=1500;public static boolean omitDNS;public LinkProperties(){}public String getInterfaceName(){return name;}public java.util.List<String> getLinkAddresses(){return java.util.List.of(address);}public boolean equals(Object o){if(!(o instanceof LinkProperties))return false;LinkProperties p=(LinkProperties)o;return name.equals(p.name)&&address.equals(p.address)&&dns.equals(p.dns)&&routes.equals(p.routes)&&mtu==p.mtu;}public int hashCode(){return java.util.Objects.hash(name,address,dns,routes,mtu);}public int describeContents(){return 0;}public void writeToParcel(android.os.Parcel p,int flags){p.writeString(name);p.writeString(address);p.writeString(dns);p.writeString(routes);p.writeInt(mtu);}public static final android.os.Parcelable.Creator<LinkProperties> CREATOR=new android.os.Parcelable.Creator<LinkProperties>(){public LinkProperties createFromParcel(android.os.Parcel p){LinkProperties value=new LinkProperties();value.name=p.readString();value.address=p.readString();value.dns=p.readString();value.routes=p.readString();value.mtu=p.readInt();if(omitDNS)value.dns="";return value;}public LinkProperties[] newArray(int count){return new LinkProperties[count];}};}''',
 'android/os/Parcelable.java':'''package android.os;public interface Parcelable {int describeContents();void writeToParcel(Parcel p,int flags);interface Creator<T>{T createFromParcel(Parcel p);T[] newArray(int count);}}''',
 'android/os/Parcel.java':'''package android.os;public final class Parcel {public static int active;public static boolean failRead;private final java.util.ArrayList<Object> values=new java.util.ArrayList<>();private int position;private boolean recycled;public static synchronized Parcel obtain(){active++;return new Parcel();}public void writeString(String value){values.add(value);}public void writeInt(int value){values.add(value);}public String readString(){if(failRead)throw new IllegalStateException("controlled parcel read failure");return (String)values.get(position++);}public int readInt(){return (Integer)values.get(position++);}public void setDataPosition(int value){if(value!=0)throw new AssertionError("unexpected parcel position");position=value;}public synchronized void recycle(){if(recycled)throw new AssertionError("parcel recycled twice");recycled=true;values.clear();synchronized(Parcel.class){active--;}}}''',
'android/net/NetworkCapabilities.java':'''package android.net;public final class NetworkCapabilities {public static final int TRANSPORT_CELLULAR=0,TRANSPORT_WIFI=1,TRANSPORT_BLUETOOTH=2,TRANSPORT_ETHERNET=3,TRANSPORT_VPN=4,NET_CAPABILITY_INTERNET=12,NET_CAPABILITY_NOT_VPN=15,NET_CAPABILITY_VALIDATED=16;public boolean vpn,validated=true;public boolean hasTransport(int t){return t==(vpn?TRANSPORT_VPN:TRANSPORT_ETHERNET);}public boolean hasCapability(int c){return c==NET_CAPABILITY_INTERNET||c==NET_CAPABILITY_NOT_VPN&&!vpn||c==NET_CAPABILITY_VALIDATED&&validated;}}''',
'android/net/NetworkRequest.java':'''package android.net;public final class NetworkRequest {int capability;public static final class Builder {NetworkRequest request=new NetworkRequest();boolean clear;public Builder clearCapabilities(){clear=true;return this;}public Builder addCapability(int c){request.capability=c;return this;}public NetworkRequest build(){if(!clear||request.capability!=NetworkCapabilities.NET_CAPABILITY_NOT_VPN)throw new AssertionError("comparison requested a VPN network");return request;}}}''',
 'android/os/Looper.java':'''package android.os;public final class Looper {private static final Looper MAIN=new Looper();public static Looper getMainLooper(){return MAIN;}}''',
 'android/os/Handler.java':'''package android.os;public final class Handler {public static final java.util.concurrent.ConcurrentLinkedQueue<Runnable> pending=new java.util.concurrent.ConcurrentLinkedQueue<>();public Handler(Looper l){}public boolean post(Runnable r){pending.add(r);return true;}public boolean postDelayed(Runnable r,long delay){pending.add(r);return true;}public static void tick(){Runnable r=pending.poll();if(r!=null)r.run();}}''',
 'android/net/ConnectivityManager.java':'''package android.net;import java.util.*;public final class ConnectivityManager {public final Network physical=new Network(21),other=new Network(22),vpn=new Network(81);public final LinkProperties link=new LinkProperties(),otherLink=new LinkProperties();public final NetworkCapabilities capabilities=new NetworkCapabilities();public NetworkCallback callback,defaults;public int registrations,removals,closeFailures;public boolean inside,includeVPN,includeOther;public Network physicalDefault=physical;public Runnable registration;
 public Network getActiveNetwork(){guard();return includeVPN?vpn:physicalDefault;}
 public Network[] getAllNetworks(){guard();ArrayList<Network> result=new ArrayList<>(List.of(physical));if(includeOther)result.add(other);if(includeVPN)result.add(vpn);return result.toArray(new Network[0]);}public NetworkCapabilities getNetworkCapabilities(Network n){guard();if(n.equals(vpn)){NetworkCapabilities c=new NetworkCapabilities();c.vpn=true;return c;}return capabilities;}public LinkProperties getLinkProperties(Network n){guard();return n.equals(other)?otherLink:link;}private void guard(){if(inside)throw new AssertionError("synchronous network lookup from callback");}
 public void registerNetworkCallback(NetworkRequest request,NetworkCallback value){if(callback!=null)throw new AssertionError("network observer leaked");registrations++;callback=value;inside=true;try{value.onAvailable(physical);value.onCapabilitiesChanged(physical,capabilities);value.onLinkPropertiesChanged(physical,link);if(includeOther){value.onAvailable(other);value.onCapabilitiesChanged(other,capabilities);value.onLinkPropertiesChanged(other,otherLink);}}finally{inside=false;}if(registration!=null)registration.run();}
 public void registerDefaultNetworkCallback(NetworkCallback value){if(defaults!=null)throw new AssertionError("default observer leaked");defaults=value;registrations++;emitDefault();}
 public void unregisterNetworkCallback(NetworkCallback value){if(closeFailures>0){closeFailures--;throw new IllegalStateException("temporary callback unregister failure");}if(callback==value)callback=null;else if(defaults==value)defaults=null;else throw new AssertionError("foreign network observer removed");removals++;}
 public void emitDefault(){Network network=getActiveNetwork();NetworkCapabilities caps=getNetworkCapabilities(network);NetworkCallback c=defaults;inside=true;try{if(c!=null){c.onAvailable(network);c.onCapabilitiesChanged(network,caps);}}finally{inside=false;}}
 public void defaultSwitch(){physicalDefault=other;emitDefault();}public void overlay(boolean on){includeVPN=on;emitDefault();}
 public void loss(){NetworkCallback c=callback;inside=true;try{if(c!=null)c.onLost(physical);}finally{inside=false;}}
 public void linkEvent(){NetworkCallback c=callback;inside=true;try{if(c!=null)c.onLinkPropertiesChanged(physical,link);}finally{inside=false;}}
 public void changedLink(){link.address="192.0.2.4/24";linkEvent();}
 public abstract static class NetworkCallback {public void onAvailable(Network n){}public void onLost(Network n){}public void onCapabilitiesChanged(Network n,NetworkCapabilities c){}public void onLinkPropertiesChanged(Network n,LinkProperties p){}}
}'''

}

RUNTIME=r'''
final class AndroidStandardExitRuntime {
 interface Callback{void progress(String s);void finished(boolean ok,String s);default void owned(String id){}}
 Context context;final java.util.concurrent.atomic.AtomicBoolean closed=new java.util.concurrent.atomic.AtomicBoolean();
 boolean disconnectRequested,revalidationTeardown,teardownInProgress;
 String torNativeSession="",externalNativeSession="",requestedExecution="local",execution="local",selected="local";
 MeasurementSource activeMeasurementSource;AndroidStandardExitStore.Entry ordinary;
 int starts,restores,compares;static final Map<String,String> winners=new HashMap<>();
 // SHIPPING_MEASUREMENT_SOURCE
 // SHIPPING_CAPTURE
 // SHIPPING_REQUIRE
 void launch(File file,AndroidStandardExitStore.Entry ordinaryEntry,AndroidStandardExitStore.Entry exit,String mode,String requested,String selected,Callback callback){
  context=NativeUsageBoundary.context;starts++;LayeredVpnService.nativePhysical=android.content.Context.network.physicalDefault;android.content.Context.network.overlay(true);try{ordinary=ordinaryEntry==null?null:AndroidStandardExitStore.copy(ordinaryEntry);}catch(Exception failure){callback.finished(false,failure.toString());return;}execution=requested;requestedExecution=requested;this.selected=selected;
  final String source;try{source=file!=null?AndroidExternalPolicy.entryDigest(file):ordinary!=null?AndroidStandardExitStore.snapshot(ordinary):"";}catch(Exception failure){callback.finished(false,failure.toString());return;}
  NativeUsageBoundary.external(file,ordinary,exit,mode,new Callback(){
   public void owned(String session){externalNativeSession=torNativeSession=session;callback.owned(session);}public void progress(String message){callback.progress(message);}
   public void finished(boolean ok,String message){try{if(ok)activeMeasurementSource=new MeasurementSource(AndroidHomeStateStore.snapshot(context),externalNativeSession,AndroidStandardExitStore.snapshot(exit),file!=null?"router-vpn":ordinary!=null?"external":"direct",source,file==null?null:file.getCanonicalFile(),execution,AndroidStandardExitRuntime.this.selected);callback.finished(ok,message);}catch(Exception failure){callback.finished(false,failure.toString());}}
  });
 }
 void connect(File f,AndroidStandardExitStore.Entry e,String mode,String execution,Callback cb){if(execution.equals("auto"))compares++;launch(f,null,e,mode,execution,execution.equals("auto")?winners.getOrDefault(e.id,"server"):execution,cb);}
 void connect(File f,AndroidStandardExitStore.Entry e,String mode,Callback cb){connect(f,e,mode,"local",cb);}void connect(File f,AndroidStandardExitStore.Entry e,Callback cb){connect(f,e,"wg",cb);}void connectDirect(AndroidStandardExitStore.Entry e,Callback cb){connect(null,e,"","local",cb);}
 void connectOrdinary(AndroidStandardExitStore.Entry e,AndroidStandardExitStore.Entry x,String execution,Callback cb){launch(null,e,x,AndroidExternalPolicy.protocol(e.protocol),execution,"local",cb);}
 void restoreCaptured(File f,AndroidStandardExitStore.Entry e,String mode,String execution,String selected,Callback cb){restores++;launch(f,null,e,mode,execution,selected,cb);}
 AndroidStandardExitStore.Entry capturedOrdinaryEntry(AndroidHomeStateStore.Snapshot home)throws Exception{return ordinary==null?null:AndroidStandardExitStore.copy(ordinary);}
 String capturedRequestedExecution(AndroidHomeStateStore.Snapshot home){return execution;}String capturedExternalExecution(AndroidHomeStateStore.Snapshot home){return selected;}
 String capturedTorExit(AndroidHomeStateStore.Snapshot home){return "8.8.4.4";}String capturedExternalExit(AndroidHomeStateStore.Snapshot home){return "8.8.4.4";}
 boolean disconnectAndDrainCaptured(String id){return ComparisonNative.stop(id);}boolean disconnectCaptured(String id){return ComparisonNative.stop(id);}void disconnect(){ComparisonNative.stop(AndroidHomeStateStore.snapshot(context).sessionId);}boolean isActiveOrTransitioning(){return false;}
}
final class ComparisonNative {
 static int stops,proofs;static boolean holdStop;static java.util.concurrent.CountDownLatch stopEntered,stopRelease;
 static boolean stop(String id){
  Context context=NativeUsageBoundary.context;if(!id.equals(AndroidHomeStateStore.snapshot(context).sessionId))return false;
  if(LayeredVpnService.current!=null&&LayeredVpnService.current.began&&!LayeredVpnService.current.drained)throw new AssertionError("native path stopped before probe drain");
  stops++;AndroidHomeStateStore.beginPathRevalidation(context,"controlled native teardown retains its exact owner");if(holdStop){stopEntered.countDown();try{if(!stopRelease.await(4,java.util.concurrent.TimeUnit.SECONDS))throw new AssertionError("stop barrier expired");}catch(InterruptedException e){throw new AssertionError(e);}}
  if(!id.equals(AndroidHomeStateStore.snapshot(context).sessionId))return false;AndroidHomeStateStore.disconnected(context);return true;
 }
}
'''

HARNESS=r'''package com.eabusham.routervpn;
import android.content.*;import android.app.*;import java.io.*;import java.nio.file.*;import java.util.*;import java.util.concurrent.*;import org.json.*;
public final class ExternalComparisonTest {
 static int checks;interface Throwing{void run()throws Exception;}static void reject(Throwing fn,String message)throws Exception{try{fn.run();}catch(Exception expected){checks++;return;}throw new AssertionError(message);}static void check(boolean value,String message){checks++;if(!value)throw new AssertionError(message);}
 interface Condition{boolean ready();}static void await(Condition condition,String message)throws Exception{long until=System.nanoTime()+5_000_000_000L;while(!condition.ready()&&System.nanoTime()<until)Thread.sleep(2);check(condition.ready(),message);}
 static JSONObject bundle()throws Exception{return new JSONObject().put("profileSchemaVersion",4).put("nodeProofId","a".repeat(64)).put("profiles",new JSONObject().put("wg",new JSONObject().put("fixture","engine-boundary"))).put("modes",new JSONArray().put(new JSONObject().put("id","wg"))).put("activeRouterProfileId","home").put("routerProfiles",new JSONArray().put(new JSONObject().put("id","home").put("name","Router entry").put("node_proof_id","a".repeat(64)).put("endpoint","192.0.2.10").put("router_api","https://192.0.2.10:8443").put("api_token","private-api-token").put("dns","home").put("mtu",1280)));}
 static final class Result implements AndroidExternalNodeComparison.Callback {volatile int calls;volatile AndroidExternalNodeComparison.Result result;volatile Throwable error;String progress="";java.util.function.Consumer<String> progressHook;public void progress(String value){progress=value;if(progressHook!=null)progressHook.accept(value);}public void finished(AndroidExternalNodeComparison.Result value,Throwable failure){result=value;error=failure;calls++;}}
 static final class Fixture {
  final Activity activity;final AndroidNodeStore nodes;final AndroidStandardExitStore exits;final AndroidNodeStore.Node entry;final AndroidStandardExitStore.Entry slow,fast;final AndroidUnifiedConnectionController connection;final AndroidExternalNodeComparison comparison;final Result result=new Result();final android.net.ConnectivityManager network=new android.net.ConnectivityManager();
  Fixture(Path root)throws Exception{
   check(!AndroidExternalNodeComparison.hasActiveOperation()&&!AndroidMTUMeasurementGate.held(),"previous comparison leaked owner or MTU lease");
   Context.preferences.clear();Context.nextFiles=Files.createTempDirectory(root,"comparison-").toFile();Context.network=network;activity=new ComparisonActivity();NativeUsageBoundary.reset(activity);AndroidVpnMutationGuard.busy=false;AndroidRuntimeRegistry.instance=new AndroidRuntimeRegistry();android.net.VpnService.needsPermission=false;android.net.VpnService.prepareCalls=android.net.VpnService.denyAfter=0;AndroidStandardExitRuntime.winners.clear();ComparisonNative.stops=ComparisonNative.proofs=0;ComparisonNative.holdStop=false;
   LayeredVpnService.reset();LayeredVpnService.automatic=0;LayeredVpnService.scores.clear();LayeredVpnService.failExit="";LayeredVpnService.restartFails=false;LayeredVpnService.wrongPhysical=false;android.os.Handler.pending.clear();android.system.Os.afterTarget="";android.system.Os.afterRename=null;
   nodes=new AndroidNodeStore(activity);exits=new AndroidStandardExitStore(activity);entry=nodes.importBundle(bundle().toString().getBytes(java.nio.charset.StandardCharsets.UTF_8));nodes.select(entry.id);
   slow=external("slow-exit");fast=external("fast-exit");exits.save(slow);exits.save(fast);LayeredVpnService.scores.put(slow.id,20d);LayeredVpnService.scores.put(fast.id,5d);
   connection=new AndroidUnifiedConnectionController(activity,nodes);comparison=new AndroidExternalNodeComparison(activity,nodes,connection);((ComparisonActivity)activity).configure(nodes,exits,connection);
  }
  AndroidStandardExitStore.Entry external(String id)throws Exception{AndroidStandardExitStore.Entry e=new AndroidStandardExitStore.Entry();e.id=id;e.name=id;e.protocol="shadowsocks";e.server="8.8.8.8";e.serverPort=443;e.method="aes-256-gcm";e.secret="private-"+id;e.expectedPublicIp="8.8.4.4";e.responseProbe=new JSONObject().put("url","https://8.8.8.8/response");e.policy=new JSONObject().put("dns_mode","custom").put("dns_protocol","udp").put("dns_host","9.9.9.9").put("dns_port",53).put("mtu_policy","auto");return e;}
  AndroidExternalNodeComparison.PathContext context(boolean paired,String execution)throws Exception{return paired?AndroidExternalNodeComparison.PathContext.saved(new AndroidConnectionProfileStore.ExternalSelection(entry,slow,"wg",execution)):AndroidExternalNodeComparison.PathContext.direct();}
  void original()throws Exception{connection.connectNode(entry,"wg",List.of(),new AndroidUnifiedConnectionController.Callback(){public void progress(String m){}public void finished(boolean ok,String m){check(ok,"original Router proof failed");}});NativeUsageBoundary.finish();}
  void start(boolean paired,String execution,boolean adopt)throws Exception{comparison.run(context(paired,execution),adopt,result);}
  void tick()throws Exception{android.os.Handler.tick();if(NativeUsageBoundary.pending!=null)NativeUsageBoundary.finish();Thread.sleep(2);}
  void pump()throws Exception{long until=System.nanoTime()+12_000_000_000L;while(result.calls==0&&System.nanoTime()<until){android.os.Handler.tick();if(NativeUsageBoundary.pending!=null)NativeUsageBoundary.finish();Thread.sleep(2);}check(result.calls==1,"batch did not finish: "+result.progress);check(!AndroidMTUMeasurementGate.held()&&!AndroidExternalNodeComparison.hasActiveOperation(),"batch leaked its retained lease");check(network.callback==null&&network.defaults==null&&network.registrations==network.removals,"physical network observer leaked");}
  int uses(String id)throws Exception{File file=nodes.usageFile();if(!file.exists())return 0;JSONArray rows=new JSONObject(Files.readString(file.toPath())).getJSONArray("records");for(int i=0;i<rows.length();i++)if(id.equals(rows.getJSONObject(i).getString("node_id")))return rows.getJSONObject(i).getInt("count");return 0;}
 }
 static void positive(Path root)throws Exception{
  for(boolean original:List.of(false,true))for(boolean paired:List.of(false,true))for(boolean adopt:List.of(false,true)){
   Fixture f=new Fixture(root);if(original)f.original();String selected=AndroidConnectionSelection.digest(f.activity,f.nodes);String old=AndroidHomeStateStore.snapshot(f.activity).sessionId;
   AndroidStandardExitRuntime.winners.put(f.fast.id,"local");f.start(paired,paired?"auto":"local",adopt);f.pump();
   if(f.result.error!=null)f.result.error.printStackTrace();check(f.result.error==null&&f.result.result!=null,"valid cohort failed: "+original+"/"+paired+"/"+adopt+" "+f.result.error);
   check(f.result.result.winner.id.equals(f.fast.id)&&f.result.result.rows.size()==2,"lowest common HTTPS trimmed mean did not win");
   check(LayeredVpnService.traffic==2&&LayeredVpnService.automatic==1,"trials duplicated native50 or released/restarted MTU between candidates");
   if(adopt){check(f.result.result.adopted&&AndroidHomeStateStore.snapshot(f.activity).activeExternalId.equals(f.fast.id),"winning path was not actually adopted");check(f.uses(f.fast.id)==1&&f.uses(f.slow.id)==0,"trial use was counted or final use missing");check(f.activity.getSharedPreferences("router-vpn-unified",0).getString("selected_id","").equals(f.fast.id),"proved winner was not remembered");if(paired)check(AndroidRuntimeRegistry.instance.standardExit.compares==2&&AndroidRuntimeRegistry.instance.standardExit.selected.equals("local"),"final winner reran Compare instead of restoring measured Local");}
   else{check(!f.result.result.adopted&&f.uses(f.fast.id)==0&&f.uses(f.slow.id)==0,"comparison-only recorded an adoption");check(AndroidConnectionSelection.digest(f.activity,f.nodes).equals(selected),"trials changed saved selection");check(AndroidHomeStateStore.snapshot(f.activity).connected==original,"original connection was not restored");if(original)check(!AndroidHomeStateStore.snapshot(f.activity).sessionId.equals(old),"original restoration reused stale proof");}
  }
 }
 static void networkCases(Path root)throws Exception{
  for(String kind:List.of("dns","routes","mtu","address","default","lost-return","native","registration")){
   Fixture f=new Fixture(root);f.network.includeOther=true;
   AndroidExternalComparisonNetwork owner=new AndroidExternalComparisonNetwork(f.activity);
   if(kind.equals("registration"))f.network.registration=()->f.network.link.dns="198.51.100.53";
   if(kind.equals("registration")){reject(owner::start,"registration race accepted changed link");owner.close();continue;}
   owner.start();owner.requireBeforeStart();String published=owner.identity();f.network.overlay(true);owner.requireCurrent();owner.requireProved(f.network.physical);check(owner.identity().equals(published),"own VPN changed physical hash");f.network.overlay(false);
   switch(kind){case "dns":f.network.link.dns="198.51.100.53";f.network.linkEvent();break;case "routes":f.network.link.routes="198.51.100.0/24";f.network.linkEvent();break;case "mtu":f.network.link.mtu=1420;f.network.linkEvent();break;case "address":f.network.changedLink();break;case "default":f.network.defaultSwitch();f.network.physicalDefault=f.network.physical;f.network.emitDefault();break;case "lost-return":f.network.loss();f.network.emitDefault();break;case "native":reject(()->owner.requireProved(f.network.other),"different native network accepted");break;}
   reject(owner::requireCurrent,"physical change was rebased: "+kind);owner.close();check(f.network.registrations==f.network.removals,"network failure leaked observers");
  }
  Fixture f=new Fixture(root);f.network.includeOther=true;AndroidExternalComparisonNetwork owner=new AndroidExternalComparisonNetwork(f.activity);owner.start();owner.requireBeforeStart();f.network.overlay(true);f.network.physicalDefault=f.network.other;f.network.emitDefault();owner.requireProved(f.network.physical);f.network.overlay(false);reject(owner::requireBeforeStart,"hidden default swap escaped next idle boundary");owner.close();
  f=new Fixture(root);f.network.overlay(true);owner=new AndroidExternalComparisonNetwork(f.activity);owner.start();f.network.overlay(false);owner.requireBeforeStart();owner.requireProved(f.network.physical);owner.close();checks++;
  final Fixture captured=new Fixture(root);
  android.net.LinkProperties.omitDNS=true;try{reject(()->new AndroidExternalComparisonNetwork(captured.activity),"incomplete parcel snapshot accepted");}finally{android.net.LinkProperties.omitDNS=false;}
  android.os.Parcel.failRead=true;try{reject(()->new AndroidExternalComparisonNetwork(captured.activity),"failed parcel snapshot accepted");}finally{android.os.Parcel.failRead=false;}
  check(android.os.Parcel.active==0,"physical snapshot leaked a Parcel on success or failure");
 }
 static void failedCandidates(Path root)throws Exception{
  Fixture f=new Fixture(root);LayeredVpnService.failExit=f.fast.id;f.start(false,"local",true);f.pump();check(f.result.error==null&&f.result.result.adopted&&f.result.result.winner.id.equals(f.slow.id),"failed candidate received a winning score");check(f.result.result.rows.stream().filter(AndroidExternalNodeComparison.Row::scored).count()==1&&f.uses(f.fast.id)==0,"failed trial was counted");
  for(String fault:List.of("49","failed","wrong-node","endpoint","icmp","stage-invalidated","stage-cancelled")){
   f=new Fixture(root);LayeredVpnService.fault=fault;f.start(false,"local",true);f.pump();check(f.result.error==null&&f.result.result.winner==null&&!f.result.result.adopted,"invalid candidate won: "+fault);check(f.result.result.rows.size()==2&&f.result.result.rows.stream().noneMatch(AndroidExternalNodeComparison.Row::scored),"invalid candidate retained a score: "+fault);check(f.uses(f.fast.id)==0&&f.uses(f.slow.id)==0&&!AndroidHomeStateStore.snapshot(f.activity).connected,"invalid cohort adopted traffic");
  }
 }
 static void driftAndDrain(Path root)throws Exception{
  for(String drift:List.of("cancel","source","entry","selection","network","native-physical","replacement")){
   Fixture f=new Fixture(root);f.network.includeOther=true;f.original();String originalSelection=AndroidConnectionSelection.digest(f.activity,f.nodes);
   LayeredVpnService.drainEntered=new CountDownLatch(1);LayeredVpnService.drainRelease=new CountDownLatch(1);f.start(true,"auto",true);NativeUsageBoundary.finish();check(LayeredVpnService.drainEntered.await(3,TimeUnit.SECONDS),"measurement did not reach actual wrapper drain");int before=ComparisonNative.stops;
   check(AndroidMTUMeasurementGate.held()&&AndroidExternalNodeComparison.hasActiveOperation()&&LayeredVpnService.automatic==0&&NativeUsageBoundary.pending==null,"next trial or MTU escaped held native drain");
   switch(drift){
    case "cancel":f.comparison.cancel();android.os.Handler.tick();break;
    case "source":File exits=new File(f.activity.getFilesDir(),"standard-exits.json");AndroidPrivateFileStore.write(exits,(Files.readString(exits.toPath())+" ").getBytes(java.nio.charset.StandardCharsets.UTF_8),512*1024);break;
    case "entry":AndroidPrivateFileStore.write(f.entry.file,(Files.readString(f.entry.file.toPath())+" ").getBytes(java.nio.charset.StandardCharsets.UTF_8),AndroidNodeStore.MAX_BUNDLE);break;
    case "selection":f.activity.getSharedPreferences("router-vpn-unified",0).edit().putString("selected_id","new-user-choice").apply();break;
    case "network":f.network.link.dns="198.51.100.53";f.network.linkEvent();break;
    case "native-physical":LayeredVpnService.nativePhysical=f.network.other;break;
    case "replacement":AndroidHomeStateStore.begin(f.activity,"user-replacement","wg","wg","replacement-node");AndroidHomeStateStore.connected(f.activity,"wg","wg","wg","","replacement-node");break;
   }
   Thread.sleep(25);check(ComparisonNative.stops==before&&AndroidMTUMeasurementGate.held(),"cancel/drift released native owner before drain");LayeredVpnService.drainRelease.countDown();f.pump();check(f.result.error!=null&&f.result.result==null&&f.uses(f.fast.id)==0&&f.uses(f.slow.id)==0,"stale round was published/adopted: "+drift);check(LayeredVpnService.traffic==1,"stale round started another probe");check(!new File(f.activity.getFilesDir(),AndroidExternalNodeStatistics.FILE_NAME).exists(),"stale/cancelled cohort installed durable candidate history: "+drift);
   if(drift.equals("replacement"))check(AndroidHomeStateStore.snapshot(f.activity).activeNodeId.equals("replacement-node"),"temporary cleanup stopped replacement owner");
   if(drift.equals("selection"))check(f.activity.getSharedPreferences("router-vpn-unified",0).getString("selected_id","").equals("new-user-choice"),"cleanup overwrote newer selection");
  }
  Fixture f=new Fixture(root);f.network.includeOther=true;LayeredVpnService.wrongPhysical=true;f.start(false,"local",true);f.pump();check(f.result.error!=null&&LayeredVpnService.traffic==0,"wrong actual native physical receipt reached measurement");
 }
 static void finalCommit(Path root)throws Exception{
  for(String fault:List.of("save","proof","new-selection","usage")){
   Fixture f=new Fixture(root);String original=AndroidConnectionSelection.digest(f.activity,f.nodes);android.content.MemoryPreferences preferences=(android.content.MemoryPreferences)f.activity.getSharedPreferences("router-vpn-unified",0);
   if(fault.equals("save"))preferences.failNext=true;
   if(fault.equals("proof"))preferences.afterCommit=()->AndroidHomeStateStore.advancePathGeneration(f.activity);
   if(fault.equals("new-selection"))preferences.afterCommit=()->{preferences.values.put("selected_id","replacement-choice");AndroidHomeStateStore.advancePathGeneration(f.activity);};
   if(fault.equals("usage"))Files.createDirectory(f.nodes.usageFile().toPath());
   f.start(false,"local",true);f.pump();
   if(fault.equals("usage")){check(f.result.error==null&&f.result.result.adopted&&f.result.result.detail().contains("usage could not be saved")&&AndroidHomeStateStore.snapshot(f.activity).activeExternalId.equals(f.fast.id),"usage failure hid/rolled back committed adoption");}
   else{check(f.result.error!=null&&f.result.result==null&&!AndroidHomeStateStore.snapshot(f.activity).connected&&f.uses(f.fast.id)==0,"uncommitted selection was adopted: "+fault);if(fault.equals("new-selection"))check(preferences.getString("selected_id","").equals("replacement-choice"),"selection rollback overwrote newer choice");else check(AndroidConnectionSelection.digest(f.activity,f.nodes).equals(original),"failed selection did not restore its owned bytes");}
  }
  Fixture f=new Fixture(root);f.start(false,"local",true);f.pump();NativeUsageBoundary.last.run();check(f.uses(f.fast.id)==1&&f.result.calls==1,"duplicate proof callback inflated final adoption");
 }
 static void cleanup(Path root)throws Exception{
  for(boolean adopt:List.of(false,true)){
   Fixture f=new Fixture(root);f.network.closeFailures=8;LayeredVpnService.restartFails=true;f.start(false,"local",adopt);
   long until=System.nanoTime()+10_000_000_000L;while(!f.result.progress.contains("cleanup is pending")&&System.nanoTime()<until)f.tick();check(f.result.calls==0&&AndroidExternalNodeComparison.hasActiveOperation()&&AndroidMTUMeasurementGate.held(),"failed unregister lost its original cleanup owner");
   Result rejected=new Result();new AndroidExternalNodeComparison(f.activity,f.nodes,f.connection).run(f.context(false,"local"),false,rejected);check(rejected.calls==1&&rejected.error!=null&&AndroidExternalNodeComparison.hasActiveOperation(),"duplicate round displaced pending cleanup");
   check(AndroidHomeStateStore.snapshot(f.activity).connected==adopt,"cleanup failure silently undid adoption");f.network.closeFailures=0;f.comparison.cancel();f.pump();check(f.result.result!=null&&f.result.result.adopted==adopt&&f.result.error!=null,"terminal cleanup warning erased committed result");check(LayeredVpnService.automatic==1&&f.uses(f.fast.id)==(adopt?1:0),"cleanup retried adoption/AutoMTU");
  }
 }
 static void staleReturnedOwner(Path root)throws Exception{
  Fixture f=new Fixture(root);f.original();f.start(false,"local",true);
  long until=System.nanoTime()+6_000_000_000L;while(android.os.Handler.pending.isEmpty()&&System.nanoTime()<until){if(NativeUsageBoundary.pending!=null)NativeUsageBoundary.finish();Thread.sleep(2);}
  check(!android.os.Handler.pending.isEmpty()&&LayeredVpnService.traffic==1,"candidate did not return exact original owner before next trial");
  AndroidHomeStateStore.begin(f.activity,"user-replacement","wg","wg",f.entry.id);AndroidHomeStateStore.connected(f.activity,"wg","wg","wg","",f.entry.id);String replacement=AndroidHomeStateStore.snapshot(f.activity).sessionId;f.pump();check(f.result.error!=null&&LayeredVpnService.traffic==1&&AndroidHomeStateStore.snapshot(f.activity).sessionId.equals(replacement),"next trial absorbed user replacement as its original baseline");
 }
 static void durableCohort(Path root)throws Exception{
  for(String fault:List.of("missing-original","existing-original","newer-write")){
   Fixture f=new Fixture(root);File file=new File(f.activity.getFilesDir(),AndroidExternalNodeStatistics.FILE_NAME);byte[] previous="{\"schema\":1,\"records\":[]}".getBytes(java.nio.charset.StandardCharsets.UTF_8),newer="{\"schema\":1,\"records\":[]} ".getBytes(java.nio.charset.StandardCharsets.UTF_8);if(fault.equals("existing-original"))AndroidPrivateFileStore.write(file,previous,192*1024);
   android.system.Os.afterTarget=file.getAbsolutePath();android.system.Os.afterRename=()->{try{f.network.link.dns="198.51.100.53";f.network.linkEvent();if(fault.equals("newer-write"))AndroidPrivateFileStore.write(file,newer,192*1024);}catch(Exception failure){throw new AssertionError(failure);}};
   f.start(false,"local",true);f.pump();check(f.result.error!=null&&f.result.result==null&&f.uses(f.fast.id)==0,"stale post-write cohort was accepted");
   if(fault.equals("missing-original"))check(!file.exists(),"postwrite network change retained new stale statistic");else check(file.exists()&&Arrays.equals(Files.readAllBytes(file.toPath()),fault.equals("newer-write")?newer:previous),"statistics rollback erased newer bytes or failed to restore original");
  }
 }
 static void permissionAndOriginal(Path root)throws Exception{
  for(String fault:List.of("cancel","deny","source")){
   Fixture f=new Fixture(root);android.net.VpnService.needsPermission=true;f.start(false,"local",true);check(f.connection.isPermissionPending()&&NativeUsageBoundary.pending==null&&LayeredVpnService.traffic==0,"comparison started before permission");
   if(fault.equals("cancel")){f.comparison.cancel();android.os.Handler.tick();}else{
    if(fault.equals("source")){File file=new File(f.activity.getFilesDir(),"standard-exits.json");AndroidPrivateFileStore.write(file,(Files.readString(file.toPath())+" ").getBytes(java.nio.charset.StandardCharsets.UTF_8),512*1024);}
    f.connection.onActivityResult(f.activity.permissionRequest,fault.equals("deny")?0:Activity.RESULT_OK);
   }
   f.pump();check(!AndroidHomeStateStore.snapshot(f.activity).connected&&LayeredVpnService.traffic==0&&f.uses(f.fast.id)==0,"cancelled/stale permission launched a candidate");
   f.connection.onActivityResult(f.activity.permissionRequest,Activity.RESULT_OK);check(NativeUsageBoundary.pending==null,"late permission result revived old trial");
  }
  for(String selected:List.of("local","server")){
   Fixture f=new Fixture(root);AndroidStandardExitRuntime.winners.put(f.slow.id,selected);f.connection.connectExternal(f.entry,f.slow,false,"wg","auto",new AndroidUnifiedConnectionController.Callback(){public void progress(String m){}public void finished(boolean ok,String m){check(ok,"original Compare proof failed");}});NativeUsageBoundary.finish();String original=AndroidHomeStateStore.snapshot(f.activity).sessionId;f.start(false,"local",false);f.pump();
   check(f.result.error==null&&AndroidHomeStateStore.snapshot(f.activity).activeExternalId.equals(f.slow.id)&&AndroidRuntimeRegistry.instance.standardExit.execution.equals("auto")&&AndroidRuntimeRegistry.instance.standardExit.selected.equals(selected),"original external Compare choice was not restored");check(AndroidRuntimeRegistry.instance.standardExit.compares==1&&!AndroidHomeStateStore.snapshot(f.activity).sessionId.equals(original),"restoration reran Compare or reused its old native proof");
  }
  Fixture f=new Fixture(root);AndroidStandardExitStore.Entry tor=f.external("tor-exit");tor.protocol="tor";tor.torPolicy=new JSONObject(tor.policy.toString()).put("dns_protocol","tcp");tor.responseProbe=null;tor.expectedPublicIp="";f.exits.save(tor);AndroidExternalNodeComparison.PathContext context=AndroidExternalNodeComparison.PathContext.saved(new AndroidConnectionProfileStore.ExternalSelection(null,f.slow,tor,"shadowsocks","local"));f.comparison.run(context,true,f.result);f.pump();check(f.result.error==null&&f.result.result.adopted&&f.result.result.winner.id.equals(tor.id)&&f.result.result.rows.stream().filter(AndroidExternalNodeComparison.Row::scored).count()==1,"ordinary-entry Tor cohort selected an incompatible graph: "+f.result.error+" "+(f.result.result==null?"missing result":f.result.result.detail()));check(f.uses(f.slow.id)==1&&f.uses(tor.id)==1&&LayeredVpnService.traffic==1,"ordinary final path did not count distinct nodes exactly once");
 }
 static void restorationPermission(Path root)throws Exception{
  for(boolean late:List.of(false,true)){
   Fixture f=new Fixture(root);f.result.progressHook=value->{if(value.startsWith("Restoring the measured winner")){if(late)android.net.VpnService.denyAfter=android.net.VpnService.prepareCalls+2;else android.net.VpnService.needsPermission=true;}};
   f.start(false,"local",true);f.pump();check(f.result.error!=null&&f.result.result==null&&!f.connection.isPermissionPending()&&f.activity.permission==null&&f.uses(f.fast.id)==0,"final restoration opened or retained a changed permission prompt");check(LayeredVpnService.traffic==2&&AndroidRuntimeRegistry.instance.standardExit.starts==2&&!AndroidHomeStateStore.snapshot(f.activity).connected,"revoked final permission adopted/replayed a winner");
  }
  for(boolean ordinary:List.of(false,true))for(boolean late:List.of(false,true)){
   Fixture f=new Fixture(root);AndroidUnifiedConnectionController.Callback original=new AndroidUnifiedConnectionController.Callback(){public void progress(String s){}public void finished(boolean ok,String message){check(ok,"external original proof setup failed");}};
   if(ordinary){AndroidStandardExitStore.Entry tor=f.external("original-tor");tor.protocol="tor";tor.responseProbe=null;tor.expectedPublicIp="";tor.torPolicy=new JSONObject(tor.policy.toString()).put("dns_protocol","tcp");f.exits.save(tor);f.connection.connectOrdinaryTor(f.slow,tor,"local",original);}else f.connection.connectExternal(null,f.slow,true,"", "local",original);
   NativeUsageBoundary.finish();f.result.progressHook=value->{if(value.contains("Restoring the exact original connection")){if(late)android.net.VpnService.denyAfter=android.net.VpnService.prepareCalls+2;else android.net.VpnService.needsPermission=true;}};
   f.start(false,"local",false);f.pump();check(f.result.error!=null&&f.result.result==null&&!f.connection.isPermissionPending()&&f.activity.permission==null&&!AndroidHomeStateStore.snapshot(f.activity).connected,"revoked original restoration opened a prompt or claimed success");
  }
  Fixture f=new Fixture(root);android.net.VpnService.needsPermission=true;f.start(false,"local",true);int oldCode=f.activity.permissionRequest;java.lang.reflect.Field field=AndroidUnifiedConnectionController.class.getDeclaredField("pendingCallback");field.setAccessible(true);AndroidUnifiedConnectionController.Callback old=(AndroidUnifiedConnectionController.Callback)field.get(f.connection);android.os.Bundle state=new android.os.Bundle();f.connection.savePending(state);
  f.comparison.cancel();f.connection.close();f.pump();check(!f.connection.isPermissionPending()&&f.result.error!=null,"Activity close stranded the comparison permission owner");
  AndroidUnifiedConnectionController newer=new AndroidUnifiedConnectionController(f.activity,f.nodes);java.util.concurrent.atomic.AtomicInteger completions=new java.util.concurrent.atomic.AtomicInteger();AndroidUnifiedConnectionController.Callback cb=new AndroidUnifiedConnectionController.Callback(){public void progress(String m){}public void finished(boolean ok,String m){completions.incrementAndGet();}};
  newer.connectExternal(null,f.fast,true,"","local",cb);check(newer.isPermissionPending()&&f.activity.permissionRequest!=oldCode,"fresh user prompt could not follow destroyed comparison");check(!newer.cancelPending(old),"old comparison callback cancelled a newer permission owner");f.connection.onActivityResult(oldCode,Activity.RESULT_OK);check(newer.isPermissionPending()&&completions.get()==0&&NativeUsageBoundary.pending==null,"late old permission revived/cancelled a newer request");check(newer.cancelPending(cb)&&completions.get()==1,"new owner could not cancel its own prompt");
 }
 static void dailyUI(Path root)throws Exception{
  Fixture f=new Fixture(root);ComparisonActivity activity=(ComparisonActivity)f.activity;activity.fastest();AlertDialog menu=AlertDialog.last;check(menu.itemsVisible()&&menu.items.length==3&&menu.items[0].contains("TCP")&&menu.items[1].contains("HTTPS"),"daily Fastest menu hid or mixed measurement families");menu.clickItem(0);check(activity.routerChoices==1&&!AndroidExternalNodeComparison.hasActiveOperation(),"Router menu unexpectedly began external trials");
  for(boolean adopt:List.of(false,true)){
   f=new Fixture(root);activity=(ComparisonActivity)f.activity;activity.fastest();AlertDialog.last.clickItem(adopt?2:1);AlertDialog contexts=AlertDialog.last;check(contexts.itemsVisible()&&contexts.items.length==1&&contexts.customTitle!=null,"external context choices hidden behind Android message");contexts.clickItem(0);AlertDialog progress=AlertDialog.last;
   long until=System.nanoTime()+12_000_000_000L;while(AndroidExternalNodeComparison.hasActiveOperation()&&System.nanoTime()<until)f.tick();check(!AndroidExternalNodeComparison.hasActiveOperation()&&activity.refreshes==1&&!progress.showing,"daily result did not join real comparison cleanup");AlertDialog completed=AlertDialog.last;check(completed.message.toString().contains("50 routed HTTPS")&&completed.message.toString().contains(adopt?"Connected and freshly proved":"original connection was restored"),"daily result omitted truthful path/metric state");check(f.uses(f.fast.id)==(adopt?1:0),"daily compare/adopt intent changed usage");
   if(!adopt){completed.getButton(AlertDialog.BUTTON_POSITIVE).performClick();AlertDialog retry=AlertDialog.last;check(AndroidExternalNodeComparison.hasActiveOperation(),"Retest did not start fresh captured round");retry.getButton(AlertDialog.BUTTON_NEGATIVE).performClick();until=System.nanoTime()+8_000_000_000L;while(AndroidExternalNodeComparison.hasActiveOperation()&&System.nanoTime()<until)f.tick();check(!AndroidExternalNodeComparison.hasActiveOperation()&&!AndroidHomeStateStore.snapshot(f.activity).connected&&f.uses(f.fast.id)==0,"daily Cancel revived/used a trial");}
  }
 }
 public static void main(String[]args)throws Exception{Path root=Path.of(args[0]);String mode=System.getProperty("fixture.case","all");if(mode.equals("all")||mode.equals("positive"))positive(root);if(mode.equals("all")||mode.equals("network"))networkCases(root);if(mode.equals("all")||mode.equals("failed"))failedCandidates(root);if(mode.equals("all")||mode.equals("drift"))driftAndDrain(root);if(mode.equals("all")||mode.equals("commit"))finalCommit(root);if(mode.equals("all")||mode.equals("cleanup"))cleanup(root);if(mode.equals("all")||mode.equals("returned"))staleReturnedOwner(root);if(mode.equals("all")||mode.equals("permission"))permissionAndOriginal(root);if(mode.equals("all")||mode.equals("ui"))dailyUI(root);if(mode.equals("all")||mode.equals("durable"))durableCohort(root);if(mode.equals("all")||mode.equals("restore-permission"))restorationPermission(root);System.out.println("Android external comparison: "+checks+" shipping lifecycle/store/usage checks PASS (native proof/traffic boundary controlled)");}
}
'''

def sources():
    ui,boundaries=U.sources()
    ui.update(NETWORK)
    ui['android/net/VpnService.java']=ui['android/net/VpnService.java'].replace('public static boolean needsPermission=true;', 'public static int prepareCalls,denyAfter;public static boolean needsPermission=true;').replace('return needsPermission?', 'prepareCalls++;return needsPermission||denyAfter>0&&prepareCalls>=denyAfter?')
    ui['android/system/Os.java']=ui['android/system/Os.java'].replace('public static volatile String holdTarget="";', 'public static volatile String afterTarget="";public static volatile Runnable afterRename;public static volatile String holdTarget="";').replace('StandardCopyOption.REPLACE_EXISTING);}', 'StandardCopyOption.REPLACE_EXISTING);if(b.equals(afterTarget)){Runnable hook=afterRename;afterRename=null;if(hook!=null)hook.run();}}')
    ui['android/content/Context.java']=ui['android/content/Context.java'].replace('public Object getSystemService(String name){return null;}','public static android.net.ConnectivityManager network;public Object getSystemService(String name){return network;}')
    ui['android/app/Activity.java']=ui['android/app/Activity.java'][:-1]+'public boolean isDestroyed(){return finished;}}'
    ui['android/content/SharedPreferences.java']=ui['android/content/SharedPreferences.java'].replace('Editor putLong(String k,long v);','Editor putLong(String k,long v);Editor putInt(String k,int v);Editor putFloat(String k,float v);')
    ui['android/app/AlertDialog.java']=ui['android/app/AlertDialog.java'].replace('public void setOnShowListener','public void setMessage(CharSequence value){message=value;}public void setOnShowListener').replace('public Builder setTitle','public Builder setCancelable(boolean value){return this;}public Builder setTitle')
    ui['android/content/MemoryPreferences.java']=ui['android/content/MemoryPreferences.java'].replace('public Editor putLong(String k,long v)', 'public Editor putInt(String k,int v){next.put(k,v);removed.remove(k);return this;}public Editor putFloat(String k,float v){next.put(k,v);removed.remove(k);return this;}public Editor putLong(String k,long v)')
    ui['android/content/MemoryPreferences.java']=ui['android/content/MemoryPreferences.java'].replace('public final Map<String,Object> values=', 'public boolean failNext;public Runnable afterCommit;public final Map<String,Object> values=').replace('public boolean commit(){synchronized(MemoryPreferences.this){', 'public boolean commit(){synchronized(MemoryPreferences.this){if(failNext){failNext=false;return false;}').replace('values.putAll(next);return true;', 'values.putAll(next);Runnable hook=afterCommit;afterCommit=null;if(hook!=null)hook.run();return true;')
    boundaries=U.S.replace_class(boundaries,'AndroidConnectionProfileStore','')
    boundaries=U.S.replace_class(boundaries,'AndroidExternalNodeComparison','')
    boundaries=boundaries.replace('return busy;','return busy||AndroidHomeStateStore.snapshot(NativeUsageBoundary.context).connected||AndroidHomeStateStore.snapshot(NativeUsageBoundary.context).phase.equals("connecting");')
    boundaries=boundaries.replace('static Runnable pending,last,beforeFinish;','static volatile Runnable pending,last,beforeFinish;')
    boundaries=boundaries.replace('AndroidHomeStateStore.disconnected(NativeUsageBoundary.context);cb.finished(true,"","stopped");','cb.finished(ComparisonNative.stop(session),"","stopped");')
    source=(JAVA/'AndroidStandardExitRuntime.java').read_text()
    runtime=RUNTIME.replace('// SHIPPING_MEASUREMENT_SOURCE',U.S.block(source,'    static final class MeasurementSource')).replace('// SHIPPING_CAPTURE',U.S.block(source,'    synchronized MeasurementSource captureMeasurementSource(')).replace('// SHIPPING_REQUIRE',U.S.block(source,'    synchronized void requireMeasurementSource('))
    boundaries=U.S.replace_class(boundaries,'AndroidStandardExitRuntime',runtime)
    policy=U.S.block(boundaries,'final class AndroidExternalPolicy')
    policy_source=(JAVA/'AndroidExternalPolicy.java').read_text()
    captured=U.S.block(policy_source,'    static final class Captured {')
    # This comparison fixture restores its original ordinary/pair selection.
    # Ordered imported compilation is exercised by the real Java/Go source gate;
    # an unexpected entry into that branch must fail, never invent a native input.
    imported_boundary='static Captured captureImportedEntry(AndroidStandardExitStore.Entry source)throws Exception{throw new AssertionError("Ordered imported source requires the actual shared-compiler composition gate");}'
    boundaries=U.S.replace_class(boundaries,'AndroidExternalPolicy',policy[:-1]+captured+imported_boundary+U.S.block(policy_source,'    static String entryDigest(')+'}')
    libbox='io/nekohasekai/libbox/Libbox.java'
    imported_methods=''.join('public static String '+method+'(String config,String capture){throw new AssertionError("Ordered imported compilation is outside ordinary comparison");}' for method in (
        'routerNodeChainImportedMemberInput','routerNodeChainImportedSOCKSMemberInput','routerNodeChainImportedCONNECTMemberInput'))
    ui[libbox]=ui[libbox].rstrip()[:-1]+imported_methods+'}'
    speed=U.S.block(R.METERS,'final class AndroidSpeedLab')
    duration=U.S.block((JAVA/'AndroidSpeedLab.java').read_text(),'    static final class DurationPolicy')
    boundaries+=speed.replace(' // PRODUCTION_DURATION',duration)+U.S.block(R.METERS,'final class AndroidHopMeasurementDialog')+U.S.block(R.METERS,'final class AndroidSpeedLabHopMeter')
    native=E.NATIVE.replace('static int captures,traffic;','static int captures,traffic,automatic;static final java.util.Map<String,Double> scores=new java.util.HashMap<>();static String failExit="";static boolean restartFails,wrongPhysical;static android.net.Network nativePhysical;static void startAutomaticMTU(){automatic++;if(restartFails)throw new IllegalStateException("Auto MTU restart failure");}')
    native=native.replace('!nativeID.equals("native-1")','!nativeID.equals(AndroidRuntimeRegistry.instance.standardExit.externalNativeSession)')
    native=native.replace('String networkIdentity(){return "c".repeat(64);}', 'String networkIdentity()throws Exception{return AndroidTorProfile.digest(java.util.List.of(android.content.Context.network.physical.toString()+":"+android.content.Context.network.link.getInterfaceName()+":"+android.content.Context.network.link.getLinkAddresses()).toString().getBytes(java.nio.charset.StandardCharsets.UTF_8));}')
    native=native.replace('require();JSONObject stats=', 'require();double score=scores.getOrDefault(exit,10d);JSONObject stats=')
    native=native.replace('.put("min_ms",1).put("median_ms",2).put("average_ms",2.1).put("p90_ms",3).put("max_ms",4)', '.put("min_ms",score/2).put("median_ms",score).put("average_ms",score).put("p90_ms",score*1.5).put("max_ms",score*2)')
    native=native.replace('.put("trimmed_mean_ms",2)', '.put("trimmed_mean_ms",score)')
    native=native.replace('switch(fault){','if(exit.equals(failExit))benchmark.put("failed",1);switch(fault){')
    native=native.replace('return current=new HopMeasurementOwner(id,exit);','return new HopMeasurementOwner(id,exit);')
    native=native.replace('!valid||current!=this','!valid||began&&current!=this')
    native=native.replace('void start(){require();began=true;','void start(){require();current=this;began=true;')
    native=native.replace('final String id,exit;', 'final android.net.Network physical=nativePhysical;final String id,exit;')
    native=native.replace('String requestID(){return id;}', 'android.net.Network physicalNetwork(){require();if(physical!=nativePhysical)throw new IllegalStateException("native physical owner changed");return wrongPhysical?android.content.Context.network.other:physical;}String requestID(){return id;}')
    boundaries=boundaries.replace('static boolean stop(String id){','static boolean stop(String id){android.content.Context.network.overlay(false);')
    product=(JAVA/'ProductActivity.java').read_text()
    activity='package com.eabusham.routervpn;import android.app.*;final class ComparisonActivity extends Activity {AndroidNodeStore nodeStore;AndroidStandardExitStore exitStore;AndroidUnifiedConnectionController connection;AndroidExternalComparisonDialog externalComparisonDialog;int routerChoices,refreshes;void configure(AndroidNodeStore n,AndroidStandardExitStore e,AndroidUnifiedConnectionController c){nodeStore=n;exitStore=e;connection=c;}void fastest(){showFastConnectMenu();}void showRouterFastConnectMenu(){routerChoices++;}void refreshAll(){refreshes++;}void toast(String message){}'
    for marker in ('    private void showFastConnectMenu(', '    private void showExternalComparison('):activity+=U.S.block(product,marker)
    ui['com/eabusham/routervpn/ComparisonActivity.java']=activity+'} final class AndroidViaEntryLatencyProbe {static boolean hasActiveOperation(){return false;}}'
    # The actual profile store validates Home policy while capturing/restoring
    # Router entries. Compile its real validator and the pure shipping layer
    # selection dependency; this fixture does not compose a Start Layer graph.
    layer=(JAVA/'AndroidStartLayer.java').read_text()
    constants=layer[layer.index('    static final String OFF'):layer.index('    static final String AES_METHOD')]
    selection='\n'.join(U.S.block(layer,marker) for marker in (
        '    static String selectedMode(', '    private static JSONObject selectedRouterProfile(',
        '    private static JSONObject requireHome(', '    private static String normalize('))
    ui['com/eabusham/routervpn/AndroidStartLayer.java']='package com.eabusham.routervpn;import org.json.JSONObject;import java.util.Locale;final class AndroidStartLayer {'+constants+selection+'}'

    return ui,boundaries,native

def main():
    jar=Path(os.environ.get('ANDROID_JSON_JAR','/usr/share/java/com.android.json.jar'))
    ui,boundaries,native=sources()
    with tempfile.TemporaryDirectory(prefix='routervpn-external-comparison-') as directory,tempfile.TemporaryDirectory(prefix='.external-comparison-json-',dir=ROOT) as validator_directory:
        root=Path(directory);validator=root/'private-json';validator_source=Path(validator_directory)/'main.go';validator_source.write_text(U.S.PRIVATE_JSON_GO.replace('4097','524289').replace('4096','524288'))
        subprocess.run(['go','build','-o',str(validator),str(validator_source)],cwd=ROOT,check=True,timeout=120)
        for name,body in ui.items():
            path=root/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_text(body)
        app=root/'com/eabusham/routervpn';app.mkdir(parents=True,exist_ok=True)
        (app/'Boundaries.java').write_text(boundaries);(app/'LayeredVpnService.java').write_text(native);(app/'ExternalComparisonTest.java').write_text(HARNESS)
        names=('AndroidPrivateFileStore','AndroidNodeUsage','AndroidHomeStateStore','AndroidNodeStore','AndroidStandardExitStore','AndroidProfileSelection','AndroidConnectionSelection','AndroidUnifiedConnectionController','AndroidNumericAddress','AndroidNativeProfilePolicy','AndroidMTUMeasurementGate','AndroidNativeHopMeasurement','AndroidExternalNodeStatistics','AndroidExternalNodeBenchmark','AndroidSpeedLabController','AndroidConnectionProfilePolicy','AndroidConnectionProfileStore','AndroidExternalComparisonNetwork','AndroidExternalNodeComparison','AndroidExternalComparisonDialog')
        for name in names:(app/(name+'.java')).write_bytes((JAVA/(name+'.java')).read_bytes())
        compile=['javac','--release','17','-encoding','UTF-8','-proc:none','-cp',str(jar),'-d',str(root/'classes'),*map(str,root.rglob('*.java'))]
        run=['java','--add-opens','java.base/java.io=ALL-UNNAMED','-Dfixture.privatejson='+str(validator),'-cp',os.pathsep.join((str(root/'classes'),str(jar))),'com.eabusham.routervpn.ExternalComparisonTest',str(root/'data')]
        (root/'data').mkdir();subprocess.run(compile,check=True,timeout=60);subprocess.run(run,check=True,timeout=120)
        mutants=(
            ("lowest score", "positive", (("AndroidExternalNodeComparison", "row.score()<best.score()", "row.score()>best.score()"),)),
            ("native physical owner", "network", (("AndroidExternalComparisonNetwork", "if(physical==null||actual==null||!physical.equals(actual))", "if(false)"),)),
            ("default-network latch", "network", (("AndroidExternalComparisonNetwork", "||physical!=null&&!physical.equals(network)", ""),)),
            ("full link policy", "network", (("AndroidExternalComparisonNetwork", "if(!closed&&!java.util.Objects.equals(links.get(network),value))", "if(false)"),("AndroidExternalComparisonNetwork", "!links.equals(now.links)||", ""))),
            ("returned original owner", "returned", (("AndroidExternalNodeComparison", "if(job.expectedHome==null||!connection.pathCurrent(job.expectedHome))", "if(false)"),("AndroidExternalNodeComparison", "if(job.original.connected()? !connection.restoredCurrent(job.original,job.expectedHome.sessionId):!connection.idleCurrent(job.expectedHome))", "if(false)"))),
            ("frozen complete sources", "drift", (("AndroidExternalNodeComparison", "||!job.exitStoreSHA.equals(digest(job.exitStore,512*1024))", ""),)),
            ("keep measured execution", "positive", (("AndroidSpeedLabController", "if(externalWork!=null&&externalWork.target!=null){connection.restoreCaptured", "if(false&&externalWork!=null&&externalWork.target!=null){connection.restoreCaptured"),)),
            ("single borrowed lease", "positive", (("AndroidSpeedLabController", "if(!borrowed){AndroidMTUMeasurementGate.release(lease);", "if(true){AndroidMTUMeasurementGate.release(lease);"),)),
            ("post-save fresh proof", "commit", (("AndroidConnectionProfileStore", "            receipt.requireAfterSelection();", "            // defect: omit final fresh proof"),)),
            ("owned selection rollback", "commit", (("AndroidConnectionProfileStore", "if(!ownsPreferences(update))", "if(false)"),)),
            ("adoption-only usage", "positive", (("AndroidUnifiedConnectionController", "default boolean recordsNodeUsage() { return false; }", "default boolean recordsNodeUsage() { return true; }"),)),
            ("retained observer cleanup", "cleanup", (("AndroidExternalNodeComparison", "if(job.cleanupAttempts<3)main.postDelayed(()->finish(job,null,null),250);\n            return;", "if(job.cleanupAttempts<3)main.postDelayed(()->finish(job,null,null),250);"),)),
            ("truthful committed result", "cleanup", (("AndroidExternalNodeComparison", "job.terminalResult=job.adopted?new Result(job):result;", "job.terminalResult=null;"),)),
            ("permission denial cancels round", "permission", (("AndroidUnifiedConnectionController", "clearPending();callback.permissionDenied();callback.finished(false,\"Android VPN permission was not granted; Router VPN stayed disconnected.\");", "clearPending();callback.finished(false,\"Android VPN permission was not granted; Router VPN stayed disconnected.\");"),)),
            ("restoration prompt race", "restore-permission", (("AndroidUnifiedConnectionController", "if(permission!=null&&callback instanceof CapturedRestoreCallback)", "if(false)"),)),
            ("Activity-close exact cancellation", "restore-permission", (("AndroidExternalNodeComparison", "activity.runOnUiThread(()->{if(trial.isRunning())trial.cancel();else finish(job,null,job.adopted?null:new java.util.concurrent.CancellationException(\"External comparison cancelled.\"));});", "main.post(()->{if(trial.isRunning())trial.cancel();else finish(job,null,job.adopted?null:new java.util.concurrent.CancellationException(\"External comparison cancelled.\"));});"),)),
            ("native physical history owner", "drift", (("AndroidExternalNodeComparison", "try{job.network.requireProved(nativeOwner.physicalNetwork());}catch(Exception stale){job.network.invalidate();throw stale;}", "job.network.requireCurrent();"),)),
            ("post-write cohort validity", "durable", (("AndroidExternalNodeStatistics", "source.requireCurrent();guard.require();", "source.requireCurrent();"),)),
            ("only owned statistics rollback", "durable", (("AndroidExternalNodeStatistics", "file.exists()&&java.util.Arrays.equals(written,AndroidPrivateFileStore.read(file,MAX_STORE))", "file.exists()"),)),
            ("native invalidation cannot score", "failed", (("AndroidExternalNodeStatistics", "||!\"complete\".equals(text(status,\"stage\"))", ""),)),
        )
        for label,case,edits in mutants:
            originals={}
            for name,old,new in edits:
                path=app/(name+'.java');source=path.read_text();originals.setdefault(path,source)
                assert source.count(old)==1, label+' source boundary moved'
                path.write_text(source.replace(old,new))
            try:
                subprocess.run(compile,check=True,timeout=60,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
                command=run[:1]+['-Dfixture.case='+case]+run[1:]
                completed=subprocess.run(command,capture_output=True,text=True,timeout=45)
                assert completed.returncode!=0 and 'AssertionError' in completed.stderr,label+' negative control escaped: '+completed.stdout+completed.stderr
                if label=='owned selection rollback':
                    assert 'selection rollback overwrote newer choice' in completed.stderr, label+' failed before its ownership assertion: '+completed.stdout+completed.stderr
            finally:
                for path,source in originals.items():path.write_text(source)
        print('Android external comparison negative controls: '+str(len(mutants))+' rejected')

if __name__=='__main__':main()
