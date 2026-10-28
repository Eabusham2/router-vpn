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
# External proof/measurement fixtures inherit this map while compiling the
# real TorSession. Keep its new source-bound validator real in those callers.
SOURCES['com/eabusham/routervpn/AndroidTorPaddingReceipt.java'] = (JAVA/'AndroidTorPaddingReceipt.java').read_text()
SOURCES['com/eabusham/routervpn/AndroidMTUSession.java'] = SOURCES['com/eabusham/routervpn/AndroidMTUSession.java'].replace('public void activateTor(AndroidTorSession tor){}', 'public int torStarts;public AndroidTorSession activatedTor;public void activateTor(AndroidTorSession tor){torStarts++;activatedTor=tor;}')
SOURCES['com/eabusham/routervpn/AndroidMTUSession.java'] = SOURCES['com/eabusham/routervpn/AndroidMTUSession.java'].replace('public void established(int mtu)throws Exception{}', 'public int establishedMTU;public void established(int mtu)throws Exception{establishedMTU=mtu;}')
SOURCES['android/net/VpnService.java'] = SOURCES['android/net/VpnService.java'].replace('public class Builder {', 'public static int requestedMTU,establishments;public class Builder {').replace('setMtu(int n){return this;}', 'setMtu(int n){requestedMTU=n;return this;}').replace('public android.os.ParcelFileDescriptor establish(){return null;}', 'public android.os.ParcelFileDescriptor establish(){establishments++;return new android.os.ParcelFileDescriptor();}')
for name in ('io/nekohasekai/libbox/RouterDNSMeasurement.java','io/nekohasekai/libbox/RouterHopMeasurement.java','com/eabusham/routervpn/AndroidMTUSession.java'):
    SOURCES[name]=SOURCES[name].replace('public void close()throws Exception{}','public int closeCalls;public boolean pendingClose;public void close()throws Exception{closeCalls++;if(pendingClose)throw new IllegalStateException("retained measurement socket close failed");}')
SOURCES['io/nekohasekai/libbox/RouterMTU.java'] = 'package io.nekohasekai.libbox;public class RouterMTU {}'
SOURCES['io/nekohasekai/libbox/RouterMTUPlatform.java'] = 'package io.nekohasekai.libbox;public interface RouterMTUPlatform {}'
SOURCES['com/eabusham/routervpn/AndroidTorProfile.java'] = '''package com.eabusham.routervpn;
final class AndroidTorProfile {
 static final String OUTBOUND="routervpn-tor-exit",SESSION_FILE="routervpn-tor.json";static final int MAX_METADATA=262144;
 static boolean isTor(String value){return "tor".equals(value)||"tor-bridge".equals(value);}
 static String execution(org.json.JSONObject metadata)throws Exception{return metadata.optString("execution","local");}
 static org.json.JSONObject session(String c,String m,String s,String mode)throws Exception{return new org.json.JSONObject(m);}
 static String strictText(byte[] b)throws Exception{return new String(b,java.nio.charset.StandardCharsets.UTF_8);}
 static String digest(byte[] b)throws Exception{return java.util.HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256").digest(b));}
}'''
SOURCES['android/content/Context.java'] = SOURCES['android/content/Context.java'].replace('return null;} public android.content.pm.PackageManager', '''return new SharedPreferences(){public Editor edit(){return new Editor(){public Editor putString(String a,String b){return this;}public void apply(){}};}};} public android.content.pm.PackageManager''')
SOURCES['android/content/Context.java'] = SOURCES['android/content/Context.java'].replace("public java.io.File getFilesDir(){return null;}", "public java.io.File files;public java.io.File getFilesDir(){return files;}").replace("public Object getSystemService(String name){return null;}", "public Object getSystemService(String name){return name.equals(NOTIFICATION_SERVICE)?new android.app.NotificationManager():new android.net.ConnectivityManager();}")
SOURCES['android/os/ParcelFileDescriptor.java'] = '''package android.os;
public class ParcelFileDescriptor implements java.io.Closeable {public boolean closed;public static ParcelFileDescriptor duplicate;public static ParcelFileDescriptor fromFd(int fd){duplicate=new ParcelFileDescriptor();return duplicate;}public java.io.FileDescriptor getFileDescriptor(){return new java.io.FileDescriptor();}public int getFd(){return 1;}public void close(){closed=true;}}'''
SOURCES['android/net/Network.java'] = '''package android.net;
public class Network {public int fdBinds,tcpBinds,udpBinds;public void bindSocket(java.io.FileDescriptor fd){fdBinds++;}public void bindSocket(java.net.Socket s){tcpBinds++;}public void bindSocket(java.net.DatagramSocket s){udpBinds++;}}'''
SOURCES['android/net/ConnectivityManager.java'] = SOURCES['android/net/ConnectivityManager.java'].replace('public Network[] getAllNetworks(){return new Network[0];}', 'public static Network[] networks=new Network[0];public Network[] getAllNetworks(){return networks;}').replace('getNetworkCapabilities(Network n){return null;}', 'getNetworkCapabilities(Network n){return java.util.Arrays.asList(networks).contains(n)?new NetworkCapabilities():null;}').replace('getLinkProperties(Network n){return null;}', 'getLinkProperties(Network n){return new LinkProperties();}')
SOURCES['com/eabusham/routervpn/AndroidStartLayerRelay.java'] = SOURCES['com/eabusham/routervpn/AndroidStartLayerRelay.java'].replace('public void close(){}', 'public boolean pending;public int closes;public void close(){closes++;if(pending)throw new IllegalStateException("unfinished relay workers");}')
SOURCES['io/nekohasekai/libbox/CommandServer.java'] = '''package io.nekohasekai.libbox;
public class CommandServer {public int closes,uncheckedCloses;public CommandServer(PlatformInterface p,CommandServerHandler h){}public void start(){}public void startOrReloadService(String c,OverrideOptions o){}public void closeService(){uncheckedCloses++;}public void close(){closes++;}public void resetNetwork(){}}'''
SOURCES['com/eabusham/routervpn/AndroidMAXProfilePreparation.java'] = SOURCES['com/eabusham/routervpn/AndroidMAXProfilePreparation.java'].replace('public Physical physical;public boolean current(boolean exact){return false;}public boolean cleanupCurrent(){return false;}public void cancel(){}', 'public Physical physical=new Physical();public boolean cancelled,sourceCurrent=true;public boolean current(boolean exact){return !cancelled&&sourceCurrent;}public boolean cleanupCurrent(){return cancelled&&sourceCurrent;}public void cancel(){cancelled=true;}')
SOURCES['io/nekohasekai/libbox/RouterTorProofRequest.java'] = r'''package io.nekohasekai.libbox;
import java.util.concurrent.*;import java.util.concurrent.atomic.*;import org.json.*;import java.time.*;
public class RouterTorProofRequest {
 public final CommandServer server;public final String session,predecessor;
 public final AtomicInteger cancels=new AtomicInteger(),closes=new AtomicInteger();public volatile boolean alive=true,ran,ignoreCancellation,pendingClose;
 public volatile String response,paddingResponse="";public volatile boolean paddingFailure;public int paddingReads;public volatile CountDownLatch entered,release;public Runnable cancelBoundary;
 public RouterTorProofRequest(CommandServer s,String id,String p){server=s;session=id;predecessor=p;}
 public String run()throws Exception {if(entered!=null){entered.countDown();release.await();}ran=true;
  if(!alive&&!ignoreCancellation)throw new IllegalStateException("cancelled");
  return response!=null?response:new JSONObject().put("session_id",session).put("is_tor",true).put("dns_proven",true).put("ip","8.8.4.4").put("checked_at",Instant.now().toString()).toString();}
 public void cancel(){cancels.incrementAndGet();if(cancelBoundary!=null)cancelBoundary.run();if(!ignoreCancellation){alive=false;if(release!=null)release.countDown();if(Libbox.dnsRelease!=null)Libbox.dnsRelease.countDown();}}
 public boolean healthy(){return alive&&ran;}
 public String paddingStatusJSON(){paddingReads++;if(paddingFailure)throw new IllegalStateException("native padding status unavailable");return paddingResponse;}
 public interface CloseBoundary{void run()throws Exception;}public CloseBoundary closeBoundary;
 public void close()throws Exception{closes.incrementAndGet();alive=false;if(closeBoundary!=null)closeBoundary.run();if(pendingClose)throw new IllegalStateException("Tor lease DELETE is unacknowledged");}
}'''
LIBBOX = SOURCES['io/nekohasekai/libbox/Libbox.java']
LIBBOX = LIBBOX.replace('public static void routerStrategyCloseService(CommandServer server)throws Exception{}', 'public static void routerStrategyCloseService(CommandServer server)throws Exception{checkedCloses++;if(failClose)throw new IllegalStateException("unconfirmed native drain");}')
LIBBOX = LIBBOX[:-1] + r'''
 public static volatile RouterTorProofRequest next,created;public static volatile int dnsCalls,checkedCloses,sourceCalls;public static String sourceResult="b".repeat(64);public static boolean sourceFailure;
 public static volatile boolean failClose,dnsFailure;public static volatile java.util.concurrent.CountDownLatch factoryEntered,factoryRelease,dnsEntered,dnsRelease;
 public static void reset(){next=null;created=null;dnsCalls=0;checkedCloses=0;sourceCalls=0;sourceFailure=false;sourceResult="b".repeat(64);failClose=false;dnsFailure=false;factoryEntered=null;factoryRelease=null;dnsEntered=null;dnsRelease=null;}
 public static String routerTorPaddingSource(String config,String profile,String session)throws Exception{sourceCalls++;if(sourceFailure||!config.equals("exact-config")||!session.equals("session-owned")||!new org.json.JSONObject(profile).getString("id").equals("exit-owned"))throw new IllegalStateException("source capture mismatch");return new org.json.JSONObject(profile).optBoolean("daita_enabled",false)?sourceResult:"";}
 public static RouterTorProofRequest routerTorCreateProof(CommandServer s,String tag,String id)throws Exception{return make(s,tag,id,"");}
 public static RouterTorProofRequest routerTorCreateProofWithPredecessor(CommandServer s,String tag,String id,String p)throws Exception{return make(s,tag,id,p);}
 private static RouterTorProofRequest make(CommandServer s,String tag,String id,String p)throws Exception{
  if(!tag.equals("routervpn-tor-exit"))throw new AssertionError("wrong Tor tag");RouterTorProofRequest r=next==null?new RouterTorProofRequest(s,id,p):next;created=r;
  if(factoryEntered!=null){factoryEntered.countDown();factoryRelease.await();}return r;
 }
 public static void routerStrategyDNSProof(CommandServer s)throws Exception{dnsCalls++;if(s!=created.server)throw new AssertionError("DNS used another native Box");if(dnsEntered!=null){dnsEntered.countDown();dnsRelease.await();}if(dnsFailure)throw new IllegalStateException("DNS failed");}
 public static RouterHopMeasurement routerTorCreateHopMeasurement(CommandServer s,RouterTorProofRequest proof,String id)throws Exception{return new RouterHopMeasurement();}
 public static RouterDNSMeasurement routerTorCreateDNSMeasurement(CommandServer s,RouterTorProofRequest proof,String id)throws Exception{return new RouterDNSMeasurement();}
 public static RouterMTU newRouterTorMTU(CommandServer s,RouterMTUPlatform platform,RouterTorProofRequest proof,String config,String profile)throws Exception{return new RouterMTU();}
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
  Fixture(boolean predecessor)throws Exception{this(predecessor,"local");}
  Fixture(boolean predecessor,String execution)throws Exception{this(predecessor,execution,null,null);}
  Fixture(boolean predecessor,String execution,Boolean enabled,Integer rate)throws Exception{JSONObject m=new JSONObject().put("session_id","session-owned").put("external_id","exit-owned").put("execution",execution);if(predecessor)m.put("predecessor_profile",new JSONObject().put("id","private-entry").put("api_token","captured-private-token"));JSONObject profile=new JSONObject().put("id","exit-owned");if(enabled!=null)profile.put("daita_enabled",enabled);if(rate!=null)profile.put("daita_rate_kbps",rate);m.put("tor_profile",profile);session=new AndroidTorSession(m,"exact-config",server,this);}
  public boolean current(AndroidTorSession s,CommandServer c){return s==session&&c==currentServer;}
  public String network(){return network;}
  RouterTorProofRequest blocked(boolean ignore){RouterTorProofRequest r=new RouterTorProofRequest(server,"session-owned","");r.entered=new CountDownLatch(1);r.release=new CountDownLatch(1);r.ignoreCancellation=ignore;Libbox.next=r;return r;}
 }
 static final class Job {final AtomicReference<Throwable> error=new AtomicReference<>();final Thread thread;
  Job(Fixture f){thread=new Thread(()->{try{f.session.prove();}catch(Throwable t){error.set(t);}},"captured-tor-proof");thread.start();}
  void finish(boolean failed)throws Exception{thread.join(2000);check(!thread.isAlive(),"proof worker escaped its join");check((error.get()!=null)==failed,"proof adopted stale completion");}
 }
 static void successes()throws Exception{
  for(String execution:new String[]{"local","server"})for(boolean entry:new boolean[]{false,true}){if(!entry&&execution.equals("server"))continue;Libbox.reset();Fixture f=new Fixture(entry,execution);check(!f.session.healthy(),"unproven session healthy");rejected(()->f.session.result("session-owned","exit-owned"));rejected(()->f.session.execution("session-owned","exit-owned"));f.session.prove();
   check(f.session.healthy()&&Libbox.dnsCalls==1,"circuit and uncached DNS not proved");check(!Libbox.created.predecessor.isEmpty()==entry,"entry proof factory dropped captured profile");
   if(entry)check(Libbox.created.predecessor.contains("captured-private-token"),"entry authentication capture lost");
   check(new JSONObject(f.session.result("session-owned","exit-owned")).getString("ip").equals("8.8.4.4"),"Tor exit mismatch");
   check(f.session.execution("session-owned","exit-owned").equals(execution),"Tor returned Local for a captured Server receipt");rejected(()->f.session.execution("other","exit-owned"));rejected(()->f.session.execution("session-owned","other"));
   rejected(()->f.session.result("other","exit-owned"));rejected(()->f.session.result("session-owned","other"));rejected(f.session::prove);
   Libbox.created.alive=false;check(!f.session.healthy(),"dead native owner stayed healthy");check(Libbox.dnsCalls==1,"health started another proof");}
 }
 static JSONObject paddingStatus(long now,int rate)throws Exception{
  return new JSONObject().put("path_checked_at",now).put("dns_checked_at",now).put("receipt",new JSONObject()
   .put("direction","outgoing").put("accounting","tor-link-cell")
   .put("session_sha256",AndroidTorProfile.digest("session-owned".getBytes(java.nio.charset.StandardCharsets.UTF_8))).put("source_sha256","b".repeat(64))
   .put("generation",1).put("rate_kbps",rate).put("channel_cells",10).put("channel_cell_bytes",5140).put("observed_at",now).put("expires_at",now+5000));
 }
 static AndroidTorPaddingReceipt paddingValidator(String policy)throws Exception{return new AndroidTorPaddingReceipt("exact-config",new JSONObject(policy).put("id","exit-owned").toString(),"session-owned","local");}
 static void paddingReceipts()throws Exception{
  final long now=1800000000000L;
  for(int saved:new int[]{0,32,64,192}){
   Libbox.reset();AndroidTorPaddingReceipt owner=paddingValidator("{\"daita_enabled\":true,\"daita_rate_kbps\":"+saved+"}");int rate=saved==0?192:saved;
   JSONObject status=paddingStatus(now,rate);owner.accept(status.toString(),now);owner.accept(status.toString(),now+1000);
   check(Libbox.sourceCalls==1,"receipt refresh reconstructed or changed native source authority");
   JSONObject next=paddingStatus(now+2000,rate);next.getJSONObject("receipt").put("channel_cells",11).put("channel_cell_bytes",5654);owner.accept(next.toString(),now+2000);
   rejected(()->owner.accept(next.toString(),now+7000));rejected(()->owner.accept(paddingStatus(now+7000,rate).toString(),now+7000));
  }
  for(String fault:new String[]{"missing","malformed","oversized","extra","extra-receipt","missing-field","direction","accounting","source","session","rate","rate-string","rate-fraction","rate-floating","generation-zero","generation-negative","generation-string","generation-overflow","cells-zero","cells-overflow","bytes-low","bytes-high","bytes-odd","bytes-string","observed-zero","observed-future","observed-stale","expired","long-ttl","proof-expiry","dns-zero","dns-newer","path-future","path-string","receipt-not-object"}){
   Libbox.reset();AndroidTorPaddingReceipt owner=paddingValidator("{\"daita_enabled\":true,\"daita_rate_kbps\":64}");JSONObject status=paddingStatus(now,64),receipt=status.getJSONObject("receipt");String text=null;
   switch(fault){
    case "missing":text="";break;case "malformed":text="{";break;case "oversized":text=" ".repeat(4097);break;
    case "extra":status.put("invented_proof",true);break;case "extra-receipt":receipt.put("trusted",true);break;case "missing-field":receipt.remove("accounting");break;
    case "direction":receipt.put("direction","both");break;case "accounting":receipt.put("accounting","UDP-bytes");break;
    case "source":receipt.put("source_sha256","c".repeat(64));break;case "session":receipt.put("session_sha256","c".repeat(64));break;
    case "rate":receipt.put("rate_kbps",192);break;case "rate-string":receipt.put("rate_kbps","64");break;case "rate-fraction":receipt.put("rate_kbps",64.5);break;case "rate-floating":text=status.toString().replace("\"rate_kbps\":64","\"rate_kbps\":64.0");break;
    case "generation-zero":receipt.put("generation",0);break;case "generation-negative":receipt.put("generation",-1);break;case "generation-string":receipt.put("generation","1");break;case "generation-overflow":text=status.toString().replace("\"generation\":1","\"generation\":9223372036854775808");break;
    case "cells-zero":receipt.put("channel_cells",0);break;case "cells-overflow":receipt.put("channel_cells",Long.MAX_VALUE);break;case "bytes-low":receipt.put("channel_cell_bytes",5118);break;case "bytes-high":receipt.put("channel_cell_bytes",5142);break;case "bytes-odd":receipt.put("channel_cell_bytes",5139);break;case "bytes-string":receipt.put("channel_cell_bytes","5140");break;
    case "observed-zero":receipt.put("observed_at",0);break;case "observed-future":receipt.put("observed_at",now+1);break;case "observed-stale":receipt.put("observed_at",now-5001);break;
    case "expired":receipt.put("expires_at",now);break;case "long-ttl":receipt.put("expires_at",now+10001);break;case "proof-expiry":status.put("dns_checked_at",now-25001);break;
    case "dns-zero":status.put("dns_checked_at",0);break;case "dns-newer":status.put("path_checked_at",now-1);break;case "path-future":status.put("path_checked_at",now+1);break;case "path-string":status.put("path_checked_at","1800000000000");break;case "receipt-not-object":status.put("receipt","unowned");break;
   }
   final String changed=text==null?status.toString():text;rejected(()->owner.accept(changed,now));rejected(()->owner.accept(paddingStatus(now,64).toString(),now));
  }
  for(String changed:new String[]{"generation","cells","bytes","observed","path","dns"}){
   Libbox.reset();AndroidTorPaddingReceipt owner=paddingValidator("{\"daita_enabled\":true,\"daita_rate_kbps\":64}");JSONObject first=paddingStatus(now,64);owner.accept(first.toString(),now);
   JSONObject next=paddingStatus(now+1000,64),receipt=next.getJSONObject("receipt");
   if(changed.equals("generation"))receipt.put("generation",2);
   if(changed.equals("cells"))receipt.put("channel_cells",9).put("channel_cell_bytes",4626);
   if(changed.equals("bytes"))receipt.put("channel_cell_bytes",5120);
   if(changed.equals("observed"))receipt.put("observed_at",now-1);
   if(changed.equals("path"))next.put("path_checked_at",now-1).put("dns_checked_at",now-1);
   if(changed.equals("dns"))next.put("dns_checked_at",now-1);
   rejected(()->owner.accept(next.toString(),now+1000));
  }
  for(String policy:new String[]{"{}","{\"daita_enabled\":false}","{\"daita_enabled\":false,\"daita_rate_kbps\":64}"}){
   Libbox.reset();AndroidTorPaddingReceipt off=paddingValidator(policy);off.accept("",now);rejected(()->off.accept(paddingStatus(now,64).toString(),now));
  }
  for(String policy:new String[]{"{\"daita_enabled\":\"true\"}","{\"daita_enabled\":null}","{\"daita_rate_kbps\":31}","{\"daita_rate_kbps\":193}","{\"daita_rate_kbps\":\"64\"}","{\"daita_rate_kbps\":64.5}"}){Libbox.reset();rejected(()->paddingValidator(policy));check(Libbox.sourceCalls==0,"malformed saved padding reached native compilation");}
  for(String source:new String[]{"","x","B".repeat(64),"b".repeat(63)}){Libbox.reset();Libbox.sourceResult=source;rejected(()->paddingValidator("{\"daita_enabled\":true}"));}
  Libbox.reset();Libbox.sourceFailure=true;rejected(()->paddingValidator("{\"daita_enabled\":true}"));
 }
 static void paddingOwnership()throws Exception{
  for(boolean entry:new boolean[]{false,true})for(int rate:new int[]{0,32,64,192}){
   Libbox.reset();Fixture f=new Fixture(entry,"local",true,rate);RouterTorProofRequest proof=new RouterTorProofRequest(f.server,"session-owned",entry?"captured-private-token":"");Libbox.next=proof;proof.paddingResponse=paddingStatus(System.currentTimeMillis(),rate==0?192:rate).toString();f.session.prove();
   check(f.session.healthy()&&proof.paddingReads==3&&Libbox.dnsCalls==1&&Libbox.sourceCalls==1,"enabled padding missed before/after-DNS or cached health receipt validation");
   proof.paddingFailure=true;check(!f.session.healthy(),"failed native status stayed Connected");check(proof.cancels.get()==1&&f.session.dataCancelled(),"failed receipt did not immediately revoke its native data owner");proof.paddingFailure=false;check(!f.session.healthy(),"failed status resurrected its retired host proof");rejected(()->f.session.result("session-owned","exit-owned"));
  }
  Libbox.reset();Fixture server=new Fixture(true,"server",true,64);server.session.prove();check(server.session.healthy()&&Libbox.sourceCalls==0,"Server cover borrowed Local source/receipt authority");Libbox.created.paddingResponse=paddingStatus(System.currentTimeMillis(),64).toString();check(!server.session.healthy(),"Local receipt replaced Server lease authority");
  for(String failure:new String[]{"missing","changed-source","failed-status"}){
   Libbox.reset();Fixture f=new Fixture(false,"local",true,64);RouterTorProofRequest proof=new RouterTorProofRequest(f.server,"session-owned","");Libbox.next=proof;
   if(failure.equals("changed-source")){JSONObject status=paddingStatus(System.currentTimeMillis(),64);status.getJSONObject("receipt").put("source_sha256","c".repeat(64));proof.paddingResponse=status.toString();}
   if(failure.equals("failed-status"))proof.paddingFailure=true;
   rejected(f.session::prove);check(!f.session.healthy()&&Libbox.dnsCalls==0,"invalid initial padding authority reached DNS/Connected");check(proof.cancels.get()==1&&f.session.dataCancelled(),"invalid initial receipt did not immediately revoke its native data owner");
  }
  for(String change:new String[]{"missing","expired","generation","source","api"}){
   Libbox.reset();Fixture f=new Fixture(false,"local",true,64);RouterTorProofRequest proof=new RouterTorProofRequest(f.server,"session-owned","");Libbox.next=proof;proof.paddingResponse=paddingStatus(System.currentTimeMillis(),64).toString();Libbox.dnsEntered=new CountDownLatch(1);Libbox.dnsRelease=new CountDownLatch(1);
   Job job=new Job(f);waitFor(Libbox.dnsEntered);JSONObject changed=paddingStatus(System.currentTimeMillis(),64);
   if(change.equals("expired"))changed.getJSONObject("receipt").put("expires_at",System.currentTimeMillis()-1);
   if(change.equals("generation"))changed.getJSONObject("receipt").put("generation",2);
   if(change.equals("source"))changed.getJSONObject("receipt").put("source_sha256","c".repeat(64));
   proof.paddingResponse=change.equals("missing")?"":changed.toString();proof.paddingFailure=change.equals("api");Libbox.dnsRelease.countDown();job.finish(true);check(!f.session.healthy(),"DNS completion adopted changed padding lease: "+change);check(proof.cancels.get()==1&&f.session.dataCancelled(),"post-DNS receipt rejection left its native data owner alive: "+change);
  }
  for(String route:new String[]{"healthy","result","execution","hop","dns","mtu-profile","mtu"}){
   Libbox.reset();Fixture f=new Fixture(false,"local",true,64);RouterTorProofRequest proof=new RouterTorProofRequest(f.server,"session-owned","");Libbox.next=proof;proof.paddingResponse=paddingStatus(System.currentTimeMillis(),64).toString();f.session.prove();
   Fixture replacement=new Fixture(false,"local",true,64);RouterTorProofRequest next=new RouterTorProofRequest(replacement.server,"session-owned","");Libbox.next=next;next.paddingResponse=paddingStatus(System.currentTimeMillis(),64).toString();replacement.session.prove();
   proof.cancelBoundary=()->check(!Thread.holdsLock(f.session),"native cancellation ran under the session monitor: "+route);proof.paddingFailure=true;
   if(route.equals("healthy"))check(!f.session.healthy(),"failed receipt remained healthy");
   else rejected(()->{switch(route){case "result":f.session.result("session-owned","exit-owned");break;case "execution":f.session.execution("session-owned","exit-owned");break;case "hop":f.session.newHopMeasurement();break;case "dns":f.session.newDNSMeasurement();break;case "mtu-profile":f.session.mtuProfile();break;case "mtu":f.session.newMTU(null);break;}});
   check(proof.cancels.get()==1&&f.session.dataCancelled(),"receipt caller did not cancel its captured request: "+route);
   check(next.cancels.get()==0&&replacement.session.healthy(),"receipt rejection cancelled a replacement native request: "+route);
   proof.paddingFailure=false;proof.alive=true;check(!f.session.healthy(),"cancelled host revived after native status recovery: "+route);
  }
  Libbox.reset();Fixture f=new Fixture(false,"local",true,64);RouterTorProofRequest proof=new RouterTorProofRequest(f.server,"session-owned","");Libbox.next=proof;proof.paddingResponse=paddingStatus(System.currentTimeMillis(),64).toString();f.session.prove();
  LayeredVpnService service=new LayeredVpnService();android.os.ParcelFileDescriptor tun=new android.os.ParcelFileDescriptor();field("torOwner").setBoolean(service,true);field("commandServer").set(service,f.server);field("torSession").set(service,f.session);field("tunDescriptor").set(service,tun);field("state").set(service,"UP");
  proof.pendingClose=true;rejected(()->close(service));check(!f.session.healthy()&&Libbox.checkedCloses==0&&!tun.closed&&field("torSession").get(service)==f.session,"unjoined Local padding released native Box or TUN");
  proof.pendingClose=false;close(service);check(proof.closes.get()==2&&Libbox.checkedCloses==1&&tun.closed,"Local padding drain did not retry its captured owner before Box/TUN");service.onDestroy();
 }
 static void responses()throws Exception{
  for(String field:new String[]{"session","false","typed","dns-missing","dns-false","dns-typed","private4","private6","loopback","hostname","legacy","mapped","empty","stale","future","extra","missing","oversized"}){
   Libbox.reset();Fixture f=new Fixture(false);RouterTorProofRequest r=new RouterTorProofRequest(f.server,"session-owned","");Libbox.next=r;
   JSONObject p=new JSONObject().put("session_id","session-owned").put("is_tor",true).put("dns_proven",true).put("ip","8.8.8.8").put("checked_at",Instant.now().toString());
   switch(field){case "session":p.put("session_id","other");break;case "false":p.put("is_tor",false);break;case "typed":p.put("is_tor","true");break;
    case "dns-missing":p.remove("dns_proven");break;case "dns-false":p.put("dns_proven",false);break;case "dns-typed":p.put("dns_proven","true");break;
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
 static void close(LayeredVpnService service)throws Exception{Method m=LayeredVpnService.class.getDeclaredMethod("closeCoreLocked");m.setAccessible(true);try{m.invoke(service);}catch(InvocationTargetException e){if(e.getCause() instanceof Error)throw (Error)e.getCause();throw (Exception)e.getCause();}}
 static void retainedClose()throws Exception{
  Libbox.reset();LayeredVpnService service=new LayeredVpnService();CommandServer server=new CommandServer(service,service);android.os.ParcelFileDescriptor tun=new android.os.ParcelFileDescriptor();
  Path folder=Files.createTempDirectory("tor-owned-java-");Files.writeString(folder.resolve("keep"),"owned metadata");field("torOwner").set(service,true);field("commandServer").set(service,server);field("tunDescriptor").set(service,tun);field("activeSession").set(service,folder.toFile());field("activeMode").set(service,"standard-direct-tor");
  Libbox.failClose=true;rejected(()->close(service));check(field("commandServer").get(service)==server&&field("torOwner").getBoolean(service),"unconfirmed Box was forgotten");
  check(!tun.closed&&field("tunDescriptor").get(service)==tun&&Files.exists(folder.resolve("keep")),"unconfirmed native drain released VPN or session");
  check(server.closes==0&&server.uncheckedCloses==0,"unchecked close bypassed quarantine");check(field("state").get(service).equals("STOPPING"),"unconfirmed drain reported terminal state");
  Libbox.failClose=false;close(service);check(field("commandServer").get(service)==null&&!field("torOwner").getBoolean(service),"proved close did not release owner");check(tun.closed&&server.closes==1&&server.uncheckedCloses==0&&Libbox.checkedCloses==2,"retained close did not retry exact Box");service.onDestroy();check(!Files.exists(folder),"proved shutdown retained temporary session");
 }
 static void retainedServerLeaseClose()throws Exception{
  Libbox.reset();Fixture f=new Fixture(true,"server");f.session.prove();RouterTorProofRequest proof=Libbox.created;
  LayeredVpnService service=new LayeredVpnService();android.os.ParcelFileDescriptor tun=new android.os.ParcelFileDescriptor();
  field("torOwner").setBoolean(service,true);field("commandServer").set(service,f.server);field("torSession").set(service,f.session);field("tunDescriptor").set(service,tun);field("state").set(service,"UP");
  proof.pendingClose=true;rejected(()->close(service));
  check(proof.closes.get()==1&&!f.session.healthy(),"Tor Server cleanup did not cancel data and wait for its lease");
  check(Libbox.checkedCloses==0&&f.server.closes==0&&!tun.closed,"Tor entry or TUN closed before DELETE acknowledgement");
  check(field("commandServer").get(service)==f.server&&field("torSession").get(service)==f.session&&field("state").get(service).equals("STOPPING"),"pending Tor lease lost its exact retained owner");
  rejected(()->f.session.execution("session-owned","exit-owned"));proof.pendingClose=false;close(service);
  check(proof.closes.get()==2&&Libbox.checkedCloses==1&&f.server.closes==1&&tun.closed,"Tor lease retry did not precede its exact Box drain");
  check(field("torSession").get(service)==null&&field("commandServer").get(service)==null,"acknowledged Tor cleanup retained old ownership");service.onDestroy();
 }
 static void retainedMeasurementsBeforeLease()throws Exception{
  for(String kind:new String[]{"hop","dns","mtu"}){
   Libbox.reset();Fixture f=new Fixture(true,"server");f.session.prove();RouterTorProofRequest proof=Libbox.created;LayeredVpnService service=new LayeredVpnService();android.os.ParcelFileDescriptor tun=new android.os.ParcelFileDescriptor();
   field("torOwner").setBoolean(service,true);field("commandServer").set(service,f.server);field("torSession").set(service,f.session);field("tunDescriptor").set(service,tun);
   RouterHopMeasurement hop=new RouterHopMeasurement();RouterDNSMeasurement dns=new RouterDNSMeasurement();AndroidMTUSession mtu=new AndroidMTUSession(service,owner->{});
   field("hopMeasurement").set(service,hop);field("dnsMeasurement").set(service,dns);field("mtuSession").set(service,mtu);
   hop.pendingClose=kind.equals("hop");dns.pendingClose=kind.equals("dns");mtu.pendingClose=kind.equals("mtu");
   proof.closeBoundary=()->{check(hop.closeCalls>0&&dns.closeCalls>0&&mtu.closeCalls>0&&!hop.pendingClose&&!dns.pendingClose&&!mtu.pendingClose,"DELETE preceded retained measurement socket drain");};
   rejected(()->close(service));check(proof.closes.get()==0&&Libbox.checkedCloses==0&&!tun.closed&&!f.session.healthy(),"failed measurement drain released lease/entry or retained data");
   check(field("commandServer").get(service)==f.server&&field(kind.equals("hop")?"hopMeasurement":kind.equals("dns")?"dnsMeasurement":"mtuSession").get(service)==(kind.equals("hop")?hop:kind.equals("dns")?dns:mtu),"failed measurement close forgot its retryable owner");
   hop.pendingClose=false;dns.pendingClose=false;mtu.pendingClose=false;close(service);
   check((kind.equals("hop")?hop.closeCalls:kind.equals("dns")?dns.closeCalls:mtu.closeCalls)==2,"retained measurement did not receive its exact close retry");
   check(proof.closes.get()==1&&Libbox.checkedCloses==1&&tun.closed,"measurement retry did not permit ordered lease/native drain");service.onDestroy();
  }
 }
 static void cleanupPhysicalAuthority()throws Exception{
  for(String execution:new String[]{"local","server"})for(boolean useMAX:new boolean[]{false,true})for(boolean explicit:new boolean[]{false,true})for(String fault:new String[]{"live","core","session","max","network","network-id","physical","deadline","max-source"}){
   if(fault.equals("max-source")&&!useMAX)continue;
   Libbox.reset();Fixture f=new Fixture(true,execution);f.session.prove();RouterTorProofRequest proof=Libbox.created;
   LayeredVpnService service=new LayeredVpnService();android.net.Network network=new android.net.Network();android.net.ConnectivityManager.networks=new android.net.Network[]{network};
   field("connectivity").set(service,new android.net.ConnectivityManager());field("torPhysicalNetwork").set(service,network);field("torOwner").setBoolean(service,true);field("commandServer").set(service,f.server);field("torSession").set(service,f.session);field("explicitStop").setBoolean(service,explicit);
   Method identity=LayeredVpnService.class.getDeclaredMethod("executionNetworkIdentity");identity.setAccessible(true);String networkIdentity=(String)identity.invoke(service);field("executionNetwork").set(service,networkIdentity);
   AndroidMAXProfilePreparation.Adopted max=useMAX?new AndroidMAXProfilePreparation.Adopted():null;if(max!=null){max.physical.network=network;field("maxSession").set(service,max);}
   Method cancel=LayeredVpnService.class.getDeclaredMethod("cancelMultihopComparison");cancel.setAccessible(true);cancel.invoke(service);check(!f.session.healthy(),"cleanup revived cancelled Tor data");
   rejected(()->service.autoDetectInterfaceControl(130));
   proof.closeBoundary=()->{
    Object cleanup=field("torCleanup").get(service);
    if(fault.equals("core"))field("commandServer").set(service,new CommandServer(null,null));
    if(fault.equals("session"))field("torSession").set(service,null);
    if(fault.equals("max"))field("maxSession").set(service,new AndroidMAXProfilePreparation.Adopted());
    if(fault.equals("network"))field("torPhysicalNetwork").set(service,new android.net.Network());
    if(fault.equals("network-id"))field("executionNetwork").set(service,"replacement-network");
    if(fault.equals("physical"))android.net.ConnectivityManager.networks=new android.net.Network[]{new android.net.Network()};
    if(fault.equals("deadline")&&cleanup!=null){Field expiry=cleanup.getClass().getDeclaredField("deadline");expiry.setAccessible(true);expiry.setLong(cleanup,System.nanoTime()-1);}
    if(fault.equals("max-source"))max.sourceCurrent=false;
    boolean admitted=execution.equals("server")&&fault.equals("live");
    try{
     // Libbox may call back on a Go worker rather than the closing Java thread.
     AtomicReference<Throwable> error=new AtomicReference<>();Thread nativeCallback=new Thread(()->{try{service.autoDetectInterfaceControl(131);service.protectRelaySocket(new java.net.Socket());service.protectRelaySocket((java.net.DatagramSocket)null);}catch(Throwable failed){error.set(failed);}},"tor-cleanup-native-callback");nativeCallback.start();nativeCallback.join(2000);
     check(!nativeCallback.isAlive(),"cleanup callback deadlocked under service close");check((error.get()==null)==admitted,"cleanup borrowed changed/unbounded owner: "+execution+"/"+useMAX+"/"+fault);
     check(network.fdBinds==(admitted?1:0)&&network.tcpBinds==(admitted?1:0)&&network.udpBinds==(admitted?1:0),"cleanup bypassed captured physical socket binding");check(!f.session.healthy(),"cleanup exposed a healthy data path");
    }finally{field("commandServer").set(service,f.server);field("torSession").set(service,f.session);field("maxSession").set(service,max);field("torPhysicalNetwork").set(service,network);field("executionNetwork").set(service,networkIdentity);android.net.ConnectivityManager.networks=new android.net.Network[]{network};if(max!=null)max.sourceCurrent=true;}
   };
   proof.pendingClose=true;rejected(()->close(service));check(field("torCleanup").get(service)==null,"pending DELETE leaked socket authority");rejected(()->service.autoDetectInterfaceControl(132));
   check(field("commandServer").get(service)==f.server&&field("torSession").get(service)==f.session,"cleanup failure discarded retained entry");
   proof.closeBoundary=null;proof.pendingClose=false;close(service);check(field("torCleanup").get(service)==null&&field("commandServer").get(service)==null,"acknowledged cleanup leaked its admission");service.onDestroy();
  }
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
 static void failedCapacityTeardown()throws Exception{
  for(boolean destroy:new boolean[]{false,true})for(boolean replacement:new boolean[]{false,true}){
   Libbox.reset();LayeredVpnService service=new LayeredVpnService();service.files=Files.createTempDirectory("tor-capacity-failure-").toFile();service.onCreate();
   CommandServer core=new CommandServer(service,service);android.os.ParcelFileDescriptor tun=new android.os.ParcelFileDescriptor();
   AndroidHomeStateStore.Snapshot home=new AndroidHomeStateStore.Snapshot();home.connected=true;home.phase="connected";home.pathProof="passed";home.sessionId="captured-home";home.activeExternalId="captured-tor";home.activeExternalProtocol="tor";
   AndroidHomeStateStore.Snapshot current=home;if(replacement){current=new AndroidHomeStateStore.Snapshot();current.connected=true;current.phase="connected";current.pathProof="passed";current.sessionId="replacement-home";current.activeExternalId="replacement-tor";}
   AndroidHomeStateStore.value=current;field("torHomeOwner").set(service,home);field("torOwner").setBoolean(service,true);field("commandServer").set(service,core);field("tunDescriptor").set(service,tun);field("state").set(service,"UP");
   Method shutdown=LayeredVpnService.class.getDeclaredMethod("shutdown",String.class,String.class);shutdown.setAccessible(true);Libbox.failClose=true;
   if(destroy)service.onDestroy();else rejected(()->shutdown.invoke(service,"FAILED","Captured 9000-byte interface readback failed"));
   check(field("commandServer").get(service)==core&&field("torHomeOwner").get(service)==home&&!tun.closed,"failed capacity drain released captured native ownership");
   check(replacement?current.connected&&current.sessionId.equals("replacement-home")&&!current.activeExternalId.isEmpty():!current.connected&&current.pathProof.equals("failed")&&!current.activeExternalId.isEmpty(),"unconfirmed Tor drain retained Connected or changed a replacement");
   Libbox.failClose=false;if(destroy)service.onDestroy();else shutdown.invoke(service,"FAILED","Captured native drain completed");
   check(core.closes==1&&tun.closed&&field("commandServer").get(service)==null,"confirmed capacity drain did not join its captured native owner");
   check(replacement?current.connected&&current.activeExternalId.equals("replacement-tor"):!current.connected&&current.activeExternalId.isEmpty(),"confirmed Tor drain cleared a replacement or retained its old identity");
   service.onDestroy();Files.delete(service.files.toPath());
  }
 }
 static void configuredOSInterface()throws Exception{
  for(int capacity:new int[]{1280,1500,9000}){
   Libbox.reset();LayeredVpnService service=new LayeredVpnService();service.files=Files.createTempDirectory("tor-builder-mtu-").toFile();service.onCreate();AndroidMTUSession mtu=new AndroidMTUSession(service,owner->{});field("mtuSession").set(service,mtu);
   RoutePrefixIterator empty=new RoutePrefixIterator(){public boolean hasNext(){return false;}public RoutePrefix next(){throw new AssertionError("empty route fixture");}};
   TunOptions options=new TunOptions(){public int getMTU(){return capacity;}public RoutePrefixIterator getInet4Address(){return empty;}public RoutePrefixIterator getInet6Address(){return empty;}public RoutePrefixIterator getInet4RouteAddress(){return empty;}public RoutePrefixIterator getInet6RouteAddress(){return empty;}public RoutePrefixIterator getInet4RouteExcludeAddress(){return empty;}public RoutePrefixIterator getInet6RouteExcludeAddress(){return empty;}public StringIterator getIncludePackage(){return new StringIterator(){public int len(){return 0;}public boolean hasNext(){return false;}public String next(){throw new AssertionError("empty package fixture");}};}public StringIterator getExcludePackage(){return getIncludePackage();}public StringIterator getDNSServerAddress(){return new StringIterator(){boolean sent;public int len(){return 1;}public boolean hasNext(){return !sent;}public String next(){sent=true;return "172.19.0.2";}};}};
   int before=android.net.VpnService.establishments;service.openTun(options);android.os.ParcelFileDescriptor descriptor=(android.os.ParcelFileDescriptor)field("tunDescriptor").get(service);
   check(android.net.VpnService.establishments==before+1&&android.net.VpnService.requestedMTU==capacity&&mtu.establishedMTU==capacity,"compiled capacity did not reach the one captured OS VPN reader");
   check(descriptor!=null&&!descriptor.closed,"OS TUN was not retained by its exact service");service.onDestroy();check(descriptor.closed,"configured capacity leaked the OS TUN on shutdown");Files.delete(service.files.toPath());
  }
 }
 static void automaticMTU()throws Exception{
  for(String changed:new String[]{"live","pending","session","exit","home","proof","generation","replaced","home-generation","home-replaced","emergency"}){
   Libbox.reset();Fixture f=new Fixture(false);f.session.prove();LayeredVpnService service=new LayeredVpnService();service.files=Files.createTempDirectory("tor-mtu-adoption-").toFile();service.onCreate();
   AndroidHomeStateStore.Snapshot home=new AndroidHomeStateStore.Snapshot();home.sessionId="home-owned";home.activeExternalId="exit-owned";home.activeExternalProtocol="tor";home.connected=true;home.pathProof="passed";AndroidHomeStateStore.value=home;AndroidHomeStateStore.emergency=false;
   AndroidMTUSession mtu=new AndroidMTUSession(service,owner->{});field("mtuSession").set(service,mtu);field("commandServer").set(service,f.server);field("torSession").set(service,f.session);field("state").set(service,"UP");
   ExecutorService worker=(ExecutorService)field("executor").get(service);CountDownLatch entered=new CountDownLatch(1),release=new CountDownLatch(1);worker.submit(()->{entered.countDown();try{release.await();}catch(Exception e){throw new AssertionError(e);}});waitFor(entered);
   if(changed.equals("pending"))home.connected=false;if(changed.equals("proof"))Libbox.created.alive=false;
   LayeredVpnService.startTorAutomaticMTU(changed.equals("session")?"other":"session-owned",changed.equals("exit")?"other":"exit-owned",changed.equals("home")?"other":"home-owned");
   if(changed.equals("generation"))((AtomicLong)field("lifecycle").get(service)).incrementAndGet();if(changed.equals("replaced"))field("torSession").set(service,null);
   if(changed.startsWith("home-")){AndroidHomeStateStore.Snapshot next=new AndroidHomeStateStore.Snapshot();next.sessionId=changed.equals("home-replaced")?"newer-owner":home.sessionId;next.pathGeneration=changed.equals("home-generation")?home.pathGeneration+1:home.pathGeneration;next.activeExternalId=home.activeExternalId;next.activeExternalProtocol=home.activeExternalProtocol;next.connected=true;next.pathProof="passed";AndroidHomeStateStore.value=next;}
   if(changed.equals("emergency"))AndroidHomeStateStore.emergency=true;
   release.countDown();worker.submit(()->{}).get(3,TimeUnit.SECONDS);check(mtu.torStarts==(changed.equals("live")?1:0),"Tor MTU adopted pending/replaced session: "+changed);
   if(changed.equals("live"))check(mtu.activatedTor==f.session,"MTU borrowed another circuit proof");service.onDestroy();AndroidHomeStateStore.emergency=false;
  }
 }
 public static void main(String[] args)throws Exception{try{successes();paddingReceipts();paddingOwnership();responses();cancellation();retainedClose();retainedServerLeaseClose();retainedMeasurementsBeforeLease();cleanupPhysicalAuthority();physicalNetwork();retainedRelayClose();failedCapacityTeardown();configuredOSInterface();automaticMTU();System.out.println("Android captured Tor proof/service lifecycle: PASS "+checks+" checks (native and OS handles doubled)");}catch(Throwable failure){failure.printStackTrace();System.exit(1);}}
}'''


def main():
    jar=Path(os.environ.get('ANDROID_JSON_JAR','/usr/share/java/com.android.json.jar'))
    if not jar.is_file() or not shutil.which('javac'):raise RuntimeError('JDK and Android JSON implementation are required')
    with tempfile.TemporaryDirectory(prefix='routervpn-tor-java-owner-') as directory:
        folder=Path(directory)
        for name,source in SOURCES.items():
            path=folder/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_text(source)
        for name in ('AndroidTorSession','AndroidTorPaddingReceipt','AndroidNumericAddress','LayeredVpnService'):
            shutil.copyfile(JAVA/(name+'.java'),folder/'com/eabusham/routervpn'/(name+'.java'))
        (folder/'com/eabusham/routervpn/TorSessionHarness.java').write_text(HARNESS)
        sources=list(map(str,folder.rglob('*.java')));classes=folder/'classes'
        compile_args=['javac','--release','17','-encoding','UTF-8','-proc:none','-cp',str(jar),'-d',str(classes),*sources]
        run_args=['java','-cp',os.pathsep.join((str(classes),str(jar))),'com.eabusham.routervpn.TorSessionHarness']
        subprocess.run(compile_args,check=True,timeout=45);subprocess.run(run_args,check=True,timeout=20)
        controls=[('AndroidTorSession.java','''            if (cancelled || !current() || !captured.healthy()) throw unavailable();
            padding.accept(captured.paddingStatusJSON(),System.currentTimeMillis());
            result = response;''','''            padding.accept(captured.paddingStatusJSON(),System.currentTimeMillis());
            result = response;''','DNS completion owner check'),
                  ('AndroidTorPaddingReceipt.java','||!sourceSHA.equals(receipt.get("source_sha256"))','','compiled padding source binding'),
                  ('AndroidTorPaddingReceipt.java','||expires<=now','','padding expiry'),
                  ('AndroidTorPaddingReceipt.java','generation!=previous.generation||','false||','stable padding lease generation'),
                  ('AndroidTorPaddingReceipt.java','if(!text.isEmpty())throw unavailable();','if(false)throw unavailable();','Off rejects an unrequested padding owner'),
                  ('AndroidTorSession.java','''            padding.accept(captured.paddingStatusJSON(),System.currentTimeMillis());
            result = response;''','''            result = response;''','post-DNS padding lease admission'),
                  ('AndroidTorSession.java','padding.accept(captured.paddingStatusJSON(), System.currentTimeMillis());','','cached health padding lease validation'),
                  ('AndroidTorSession.java','''        captured.cancel();
        return false;''','''        return false;''','receipt rejection revokes captured native data'),
                  ('AndroidTorSession.java','''            rejectCaptured(captured);
            throw invalid;''','''            throw invalid;''','initial proof failure revokes captured native data'),
                  ('LayeredVpnService.java','Libbox.routerStrategyCloseService(commandServer);','commandServer.closeService();','checked native close'),
                  ('LayeredVpnService.java','capturedTor.close();','capturedTor.cancel();','Tor Server lease acknowledgement before native close'),
                  ('LayeredVpnService.java','captured.bindSocket(borrowed.getFileDescriptor());','','captured physical network binding'),
                  ('LayeredVpnService.java','finally{torCleanup=null;}','finally{}','bounded cleanup admission cleared on failure'),
                  ('LayeredVpnService.java','closeTorMeasurementsLocked();','','measurement drain before Tor lease DELETE'),
                  ('LayeredVpnService.java','System.nanoTime()<captured.deadline','true','cleanup deadline'),
                  ('LayeredVpnService.java','!captured.cleanupCurrent()','false','cancelled MAX cleanup source'),
                  ('LayeredVpnService.java','(stopped&&!torCleanupCurrent())','stopped','exact cancelled Server cleanup authority'),
                  ('LayeredVpnService.java','||!service.ownsTorMTUHome()','','Tor MTU Home generation ownership'),
                  ('LayeredVpnService.java','AndroidHomeStateStore.failedTorExternal(this,torHome,error.isEmpty()?"The captured Tor VPN is stopping; its path proof is no longer valid.":error,false);','','Tor failed-capacity pre-drain invalidation'),
                  ('LayeredVpnService.java','AndroidHomeStateStore.failedTorExternal(this,torHome,"The captured Tor VPN service stopped; its path proof is no longer valid.",false);','','Tor destroy pre-drain invalidation'),
                  ('LayeredVpnService.java','.setMtu(options.getMTU())','.setMtu(1280)','captured OS interface capacity')]
        for name,old,new,label in controls:
            path=folder/'com/eabusham/routervpn'/name;original=path.read_text();assert original.count(old)==1,label
            path.write_text(original.replace(old,new));subprocess.run(compile_args,check=True,timeout=45)
            result=subprocess.run(run_args,capture_output=True,text=True,timeout=20);assert result.returncode!=0 and 'AssertionError' in result.stderr,label+' control escaped'
            path.write_text(original)
        print(f'Android Tor lifecycle negative controls: PASS ({len(controls)} broken proof, lease cleanup, close, network, MTU, OS capacity and failed-capacity guards rejected)')


if __name__=='__main__':main()
