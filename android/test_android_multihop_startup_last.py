#!/usr/bin/env python3
"""Execute the shipping two-Router runtime's historical-choice boundary.

The whole runtime and its MTU transaction gate are compiled unchanged. The
controller's real Source, bounded reader and public-pin validator execute over
real files and Android JSON. Native graph compilation, Android service/proof
handles and the separate historical-record store are explicit boundaries. This
does not claim packet negotiation, Android permission or device acceptance.
"""
from pathlib import Path
import os
import re
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
JAVA = ROOT / 'android/app/src/main/java/com/eabusham/routervpn'


def member(source, marker):
    start = source.index(marker)
    brace = source.index('{', start)
    depth, end = 1, brace + 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[start:end]


STUBS = r'''package com.eabusham.routervpn;
import android.content.Context;import android.util.Base64;import java.io.*;import java.nio.charset.StandardCharsets;
import java.nio.file.*;import java.util.*;import java.util.concurrent.*;import org.json.*;
final class NativeSingBoxController {
 // NATIVE_PREDICATES
 static final class ModeInfo{}
 static final class SessionInfo{final String sessionId;SessionInfo(String s){sessionId=s;}}
 volatile String state="DOWN";int starts,stops,leases;volatile boolean failProof,failStop;
 volatile Runnable duringStart,duringStop;volatile CountDownLatch stopEntered,stopRelease;
 void start(SessionInfo session){starts++;if(AndroidMultihopController.lastExecution.equals("server"))leases++;state="UP";LayeredVpnService.nativeGeneration++;if(duringStart!=null)duringStart.run();}
 void stop(){stops++;if(stopEntered!=null){stopEntered.countDown();boolean interrupted=false;while(true){try{stopRelease.await();break;}catch(InterruptedException e){interrupted=true;}}if(interrupted)Thread.currentThread().interrupt();}if(duringStop!=null)duringStop.run();if(failStop)throw new IllegalStateException("unjoined native owner");state="DOWN";}
 String getState(){return state;}String getError(){return "native failed";}
}
final class AndroidNativeMAXProfile{ // MAX_PREDICATE
}
final class AndroidNativeCompositeProfile{ // COMPOSITE_PREDICATE
}
final class AndroidStandardExitStore {static final class Entry{String id,name,protocol;String secret="original imported source";}}
final class AndroidPrivateFileStore {static byte[] read(File f,int max)throws Exception{byte[] data=Files.readAllBytes(f.toPath());if(data.length==0||data.length>max)throw new IllegalArgumentException("bounded source required");return data;}}
final class AndroidNodeStore {
 static final int MAX_BUNDLE=32*1024*1024;
 static final class Node{final String id,name;final File file;Node(String id,File file){this.id=id;name=id;this.file=file;}}
 static void validateBundle(JSONObject b)throws Exception{b.getJSONObject("profiles");b.getJSONArray("modes");if(b.getString("node_id").isEmpty())throw new IllegalArgumentException("missing paired node");}
}
final class AndroidImportedRouterPath {
 // SHIPPING_IMPORTED_SUPPORTS
 static AndroidStandardExitStore.Entry current;
 static String snapshot(AndroidStandardExitStore.Entry e){return e.id+"/"+e.protocol+"/"+e.secret;}

 static final class PreparationFailure extends Exception{final String sessionId="";}
 static AndroidMultihopController.Source captureSource(Context c,AndroidStandardExitStore.Entry e)throws Exception{if(current!=e)throw new IllegalStateException("foreign imported record");String original=snapshot(e);return new AndroidMultihopController.Source(e.id,e.name,original.getBytes(StandardCharsets.UTF_8),()->{if(current==null||!original.equals(snapshot(current)))throw new IllegalStateException("changed imported source");});}
 static AndroidStandardExitStore.Entry entry(Context c,AndroidMultihopController.Source s)throws Exception{s.require(null);return current;}
 static AndroidMultihopController.Prepared prepare(Context c,AndroidMultihopController.Source e,File x,String mode,String execution,AndroidMultihopController.Source last)throws Exception{if(AndroidMultihopController.onPrepare!=null)AndroidMultihopController.onPrepare.run();e.require(null);last.require(x);if(!execution.equals("local")||!supports(current.protocol,mode))throw new IllegalStateException("unowned imported preparation");AndroidMultihopController.preparations++;AndroidMultihopController.lastExecution=execution;AndroidMultihopController.lastEntryMode=AndroidExternalPolicy.protocol(current.protocol);AndroidMultihopController.lastExitMode=mode;return new AndroidMultihopController.Prepared(null,x,mode,e,last);}
}
final class AndroidMultihopController {
 private static final int MAX_BUNDLE=32*1024*1024;
 // REAL_SOURCE_MEMBERS
 static String lastExecution="",lastEntryMode="",lastExitMode="",lastPins="";static int preparations;static boolean capturedInputs;
 static volatile Runnable onPrepare;
 static final class Prepared{final NativeSingBoxController.SessionInfo session;final File exitBundle;final String exitMode;final Source entrySource,exitSource;
  Prepared(File a,File b,String mode,Source x,Source y){session=new NativeSingBoxController.SessionInfo("fresh-native-"+preparations);exitBundle=b;exitMode=mode;entrySource=x;exitSource=y;}}
 AndroidMultihopController(Context c,NativeSingBoxController nativeOwner){}
 List<NativeSingBoxController.ModeInfo> listSupportedExitModes(File f){return Collections.emptyList();}
 Prepared prepare(File a,File b,String exit,String execution,String entry)throws Exception{return prepare(a,b,exit,execution,entry,null,null,null);}
 Prepared prepare(File a,File b,String exit,String execution,String entry,Source expectedA,Source expectedB,String pins)throws Exception{
  if(onPrepare!=null)onPrepare.run();LoadedBundle first=new LoadedBundle(a),last=new LoadedBundle(b);
  if(first.bundle.getString("node_id").equals(last.bundle.getString("node_id")))throw new IllegalArgumentException("duplicate paired identities");
  capturedInputs=expectedA!=null||expectedB!=null||pins!=null;
  if(capturedInputs&&(expectedA==null||expectedB==null||pins==null||!expectedA.same(first.source)||!expectedB.same(last.source)))throw new IllegalStateException("captured graph source changed");
  if(pins!=null)pins=validatedServerIdentityPins(execution,exit,pins);
  preparations++;lastExecution=execution;lastEntryMode=entry;lastExitMode=exit;lastPins=pins==null?"":pins;
  return new Prepared(a,b,exit,first.source,last.source);
 }
}
final class AndroidHomeStateStore {
 static final class Snapshot{boolean connected;long pathGeneration;String sessionId="idle",phase="off",logicalMode="",activeEntryId="",activeExitId="",activeEntryMode="wg",runtimeMode="";}
 static volatile Snapshot current=new Snapshot();static int sequence;static boolean emergency;
 static synchronized Snapshot snapshot(Context c){return current;}
 static synchronized boolean emergencyDisconnectPending(Context c){return emergency;}
 static synchronized String beginMultihop(Context c,String a,String b,String mode,String entry){Snapshot h=new Snapshot();h.sessionId="home-"+(++sequence);h.phase="connecting";h.logicalMode="multihop";h.activeEntryId=a;h.activeExitId=b;h.runtimeMode=mode;h.activeEntryMode=entry;current=h;return h.sessionId;}
 static synchronized void connectedMultihop(Context c,String a,String b,String mode,String entry){Snapshot h=current;if(!a.equals(h.activeEntryId)||!b.equals(h.activeExitId)||!mode.equals(h.runtimeMode)||!entry.equals(h.activeEntryMode))throw new AssertionError("adopted wrong Home");h.connected=true;h.phase="connected";}
 static synchronized void beginPathRevalidation(Context c,String reason){current.connected=false;current.phase="connecting";current.pathGeneration++;}
 static synchronized void failed(Context c,String reason){current.connected=false;current.phase="failed";}
 static synchronized void warning(Context c,String reason){}
 static synchronized void disconnected(Context c){current=new Snapshot();}
}
final class LayeredVpnService {
 static boolean discardPreparedSession(Context c,String session){return true;}
 static String selected="",pins="{}";static boolean unhealthy,wrongGeneration;static int nativeGeneration,captures,mtu;
 static volatile Runnable duringCapture,duringMTU;
 static final class CapturedMultihop{
  final String homeSession,entryId,exitId,entryMode,exitMode,execution,serverIdentityPins;final long pathGeneration;final int nativeOwner;
  CapturedMultihop(AndroidHomeStateStore.Snapshot h){homeSession=h.sessionId;entryId=h.activeEntryId;exitId=h.activeExitId;entryMode=h.activeEntryMode;exitMode=h.runtimeMode;pathGeneration=h.pathGeneration+(wrongGeneration?1:0);nativeOwner=nativeGeneration;execution=selected.isEmpty()?AndroidMultihopController.lastExecution:selected;serverIdentityPins=pins;}
  boolean matchesHome(AndroidHomeStateStore.Snapshot h){return h.connected&&homeSession.equals(h.sessionId)&&pathGeneration==h.pathGeneration&&entryId.equals(h.activeEntryId)&&exitId.equals(h.activeExitId)&&entryMode.equals(h.activeEntryMode)&&exitMode.equals(h.runtimeMode);}
  boolean sameOwner(CapturedMultihop other){return other!=null&&nativeOwner==other.nativeOwner&&homeSession.equals(other.homeSession)&&pathGeneration==other.pathGeneration&&execution.equals(other.execution)&&serverIdentityPins.equals(other.serverIdentityPins);}
 }
 static CapturedMultihop capturedMultihop(String home)throws Exception{captures++;AndroidHomeStateStore.Snapshot h=AndroidHomeStateStore.current;if(unhealthy||!h.connected||!home.equals(h.sessionId)||AndroidPathProbe.proofs==0)throw new IllegalStateException("fresh native graph not proved");CapturedMultihop result=new CapturedMultihop(h);if(duringCapture!=null)duringCapture.run();return result;}
 static String capturedMultihopExecution(String home)throws Exception{return capturedMultihop(home).execution;}
 static void startAutomaticMTU(){if(duringMTU!=null)duringMTU.run();if(!AndroidHomeStateStore.current.connected||captures==0)throw new AssertionError("activation preceded actual native capture");mtu++;}
 static void startMultihopAutomaticMTU(CapturedMultihop owner)throws Exception{if(duringMTU!=null)duringMTU.run();if(owner==null||!owner.sameOwner(capturedMultihop(owner.homeSession)))throw new IllegalStateException("captured MTU owner retired");mtu++;}
}
final class AndroidPathProbe{static int proofs;static boolean valid=true;static Runnable duringProof;static boolean prove(File f,int timeout){proofs++;if(duringProof!=null)duringProof.run();return valid;}}
// The actual disk format/selection policy has its separate StartupPolicy gate.
// These hooks prove that the shipping runtime does not invert store/native locks
// or write a record before its fresh native owner and public pins are accepted.
final class AndroidStartupPolicy{
 static Object runtime;static int prepares,writes;static String selected="",pins="";static Runnable onPrepare,onRecord;static boolean writeFailure;
 static final class MultihopLast{final String entry,exit,mode,requested,a,b;MultihopLast(AndroidNodeStore.Node e,AndroidNodeStore.Node x,String m,String r,AndroidMultihopController.Source a,AndroidMultihopController.Source b){entry=e.id;exit=x.id;mode=m;requested=r;this.a=a.digest;this.b=b.digest;}}
 static MultihopLast prepareMultihopExecution(Context c,AndroidNodeStore.Node e,AndroidNodeStore.Node x,String em,String xm,String requested,AndroidMultihopController.Source a,AndroidMultihopController.Source b){
  if(Thread.holdsLock(runtime)||Thread.holdsLock(AndroidHomeStateStore.class)||AndroidPathProbe.proofs==0)throw new AssertionError("Last preparation ran under runtime/Home lock or before private path proof");
  prepares++;if(onPrepare!=null)onPrepare.run();return new MultihopLast(e,x,xm,requested,a,b);
 }
 static boolean recordMultihopExecution(Context c,MultihopLast record,AndroidHomeStateStore.Snapshot home,String chosen,String identities){
  if(record==null)return false;if(!Thread.holdsLock(runtime)||!home.connected||home!=AndroidHomeStateStore.current||LayeredVpnService.captures==0||LayeredVpnService.mtu!=0)throw new AssertionError("Last record escaped exact native adoption");
  if(!record.entry.equals(home.activeEntryId)||!record.exit.equals(home.activeExitId)||!record.mode.equals(home.runtimeMode))throw new AssertionError("Last record changed path");
  if(!writeFailure){writes++;selected=chosen;pins=identities;}if(onRecord!=null)onRecord.run();return !writeFailure;
 }
}
'''

STUBS += '\nfinal class AndroidExternalPolicy {' + member((JAVA / 'AndroidExternalPolicy.java').read_text(), '    static String protocol(') + '}\n'

HARNESS = r'''package com.eabusham.routervpn;
import android.content.Context;import java.io.*;import java.nio.file.*;import java.nio.charset.StandardCharsets;import java.util.*;import java.util.concurrent.*;import java.lang.reflect.*;import org.json.*;
public final class MultihopStartupLastTest{
 static int checks,cases;static void check(boolean ok,String message){checks++;if(!ok)throw new AssertionError(message);}
 interface Run{void run()throws Exception;}static void rejected(String label,Run operation)throws Exception{boolean rejected=false;try{operation.run();}catch(Exception expected){rejected=true;}check(rejected,"invalid historical capture accepted: "+label);cases++;}
 static String publicKey(int seed){byte[] b=new byte[32];Arrays.fill(b,(byte)seed);return java.util.Base64.getEncoder().encodeToString(b);}
 static String pins(String execution,String mode)throws Exception{JSONObject p=new JSONObject();if(execution.equals("server")&&(NativeSingBoxController.nativeWireGuardFamily(mode)||NativeSingBoxController.nativePQFamily(mode)||AndroidNativeMAXProfile.isMode(mode)))p.put("expected_packet_public_key",publicKey(9));if(execution.equals("server")&&(NativeSingBoxController.nativePQFamily(mode)||AndroidNativeMAXProfile.isMode(mode)))p.put("expected_pq_client_identity","ab".repeat(32));return p.toString();}
 static final class Callback implements AndroidMultihopRuntime.Callback{final CountDownLatch done=new CountDownLatch(1);boolean ok;int completions;String owner="";public void owned(String s){owner=s;}public void progress(String s){}public void finished(boolean success,String message){ok=success;completions++;done.countDown();}void await()throws Exception{check(done.await(4,TimeUnit.SECONDS),"runtime did not finish bounded fixture");check(completions==1,"completion was not one-shot");}}
 static final class Fixture implements AutoCloseable{
  final Context context=new Context();final NativeSingBoxController engine=new NativeSingBoxController();final AndroidMultihopRuntime runtime;
  final Path directory;final AndroidNodeStore.Node entry,exit;final byte[] a,b;
  Fixture()throws Exception{
   AndroidHomeStateStore.current=new AndroidHomeStateStore.Snapshot();AndroidHomeStateStore.emergency=false;
   LayeredVpnService.selected="";LayeredVpnService.pins="{}";LayeredVpnService.unhealthy=false;LayeredVpnService.wrongGeneration=false;LayeredVpnService.captures=0;LayeredVpnService.mtu=0;LayeredVpnService.duringCapture=null;LayeredVpnService.duringMTU=null;
   AndroidMultihopController.preparations=0;AndroidMultihopController.lastExecution="";AndroidMultihopController.lastPins="";AndroidMultihopController.capturedInputs=false;AndroidMultihopController.onPrepare=null;
   AndroidPathProbe.proofs=0;AndroidPathProbe.valid=true;AndroidPathProbe.duringProof=null;AndroidStartupPolicy.prepares=0;AndroidStartupPolicy.writes=0;AndroidStartupPolicy.onPrepare=null;AndroidStartupPolicy.onRecord=null;AndroidStartupPolicy.writeFailure=false;
   directory=Files.createTempDirectory("multihop-last-files-");a=source("entry",1);b=source("exit",2);entry=new AndroidNodeStore.Node("entry",directory.resolve("entry.json").toFile());exit=new AndroidNodeStore.Node("exit",directory.resolve("exit.json").toFile());Files.write(entry.file.toPath(),a);Files.write(exit.file.toPath(),b);
   runtime=new AndroidMultihopRuntime(context,engine);AndroidStartupPolicy.runtime=runtime;
  }
  static byte[] source(String id,int version)throws Exception{return new JSONObject().put("node_id",id).put("profiles",new JSONObject().put("routervpn.json",new JSONObject().put("secret","private-"+id).put("version",version))).put("modes",new JSONArray()).toString().getBytes(StandardCharsets.UTF_8);}
  AndroidMultihopRuntime.StartupCapture capture(String em,String xm,String policy,String selected)throws Exception{return AndroidMultihopRuntime.startupCapture(entry,exit,xm,policy,em,selected,pins(selected,xm),a,b);}
  Callback last(AndroidMultihopRuntime.StartupCapture capture)throws Exception{LayeredVpnService.selected=capture.selected;LayeredVpnService.pins=capture.serverIdentityPins;Callback c=new Callback();runtime.connectLast(entry,exit,capture,AndroidHomeStateStore.snapshot(context),c);return c;}
  void change(boolean first){try{Files.write((first?entry:exit).file.toPath(),source(first?"entry":"exit",3));}catch(Exception e){throw new AssertionError(e);}}
  void idle()throws Exception{long end=System.nanoTime()+TimeUnit.SECONDS.toNanos(3);while(runtime.isActiveOrTransitioning()&&System.nanoTime()<end)Thread.yield();check(!runtime.isActiveOrTransitioning(),"retired runtime kept a joined graph");}
  public void close()throws Exception{engine.failStop=false;if(engine.stopRelease!=null)engine.stopRelease.countDown();runtime.close();idle();Files.deleteIfExists(entry.file.toPath());Files.deleteIfExists(exit.file.toPath());Files.deleteIfExists(directory);}
 }
 static AndroidStandardExitStore.Entry imported(){AndroidStandardExitStore.Entry e=new AndroidStandardExitStore.Entry();e.id="saved-import";e.name="Original import";e.protocol="socks5";AndroidImportedRouterPath.current=e;return e;}
 static void importedRuntime()throws Exception{
  for(String protocol:new String[]{"socks5","http","https"})for(String mode:protocol.equals("socks5")?new String[]{"shadowsocks","hysteria2","wg","awg2-fast","awg2-strong"}:new String[]{"shadowsocks"})try(Fixture f=new Fixture()){
   AndroidStandardExitStore.Entry e=imported();e.protocol=protocol;Callback c=new Callback();f.runtime.connectImported(e,f.exit,mode,"local",c);c.await();
   check(c.ok&&f.engine.starts==1&&AndroidMultihopController.preparations==1,"supported SOCKS imported runtime rejected before preparation: "+mode);
   check(AndroidPathProbe.proofs==1&&LayeredVpnService.mtu==1&&AndroidStartupPolicy.writes==0,"imported runtime skipped owned proof/activation or borrowed paired history");
   check(AndroidHomeStateStore.current.activeEntryId.equals(e.id)&&AndroidHomeStateStore.current.activeEntryMode.equals(AndroidExternalPolicy.protocol(protocol))&&AndroidHomeStateStore.current.runtimeMode.equals(mode),"imported runtime substituted source or final mode");cases++;
  }
  for(String protocol:new String[]{"socks5","http","https"})for(String fault:new String[]{"unsupported-entry","unsupported-final","server","auto","same-id","foreign-source","queued-entry","queued-exit","queued-cancel","prepared-entry","started-entry","private-proof"})try(Fixture f=new Fixture()){
   AndroidStandardExitStore.Entry e=imported();e.protocol=protocol;String mode=protocol.equals("socks5")?"wg":"shadowsocks",execution="local";
   if(fault.equals("unsupported-entry"))e.protocol="openvpn";if(fault.equals("unsupported-final"))mode="naive-h3";
   if(fault.equals("server")||fault.equals("auto"))execution=fault;if(fault.equals("same-id"))e.id=f.exit.id;if(fault.equals("foreign-source"))AndroidImportedRouterPath.current=null;
   if(fault.equals("prepared-entry"))AndroidMultihopController.onPrepare=()->e.secret="replaced before staging";
   if(fault.equals("started-entry"))f.engine.duringStart=()->e.secret="replaced after native start";
   if(fault.equals("private-proof"))AndroidPathProbe.valid=false;
   CountDownLatch entered=new CountDownLatch(1),release=new CountDownLatch(1);
   if(fault.startsWith("queued-")){Field field=AndroidMultihopRuntime.class.getDeclaredField("executor");field.setAccessible(true);((ExecutorService)field.get(f.runtime)).submit(()->{entered.countDown();try{release.await();}catch(InterruptedException interrupted){Thread.currentThread().interrupt();}});check(entered.await(3,TimeUnit.SECONDS),"imported queue barrier not acquired");}
   Callback c=new Callback();try{f.runtime.connectImported(e,f.exit,mode,execution,c);if(fault.equals("queued-entry"))e.secret="replacement";if(fault.equals("queued-exit"))f.change(false);if(fault.equals("queued-cancel"))f.runtime.disconnect();}finally{release.countDown();}c.await();
   boolean launched=fault.equals("started-entry")||fault.equals("private-proof");
   check(!c.ok&&f.engine.starts==(launched?1:0)&&!AndroidHomeStateStore.current.connected&&LayeredVpnService.mtu==0,"invalid imported source/execution escaped runtime: "+fault);
   if(launched)check(f.engine.stops==1,"failed imported proof did not join original native owner");cases++;
  }
 }
 static void historicalMatrix()throws Exception{
  for(String entry:new String[]{"wg","wg-pq","max-quic-awg","reality-xhttp","naive-h3","max"})for(String exit:new String[]{"wg","awg2-strong","wg-pq","awg2-pq","max-tls-wg","max-quic-awg","shadowsocks","reality-xhttp","max","split"})for(String selected:new String[]{"local","server"}){
   try(Fixture f=new Fixture()){int generation=LayeredVpnService.nativeGeneration;AndroidMultihopRuntime.StartupCapture historical=f.capture(entry,exit,"auto",selected);Callback c=f.last(historical);c.await();
    check(c.ok,"valid historical choice failed "+entry+"/"+exit+"/"+selected);check(AndroidMultihopController.lastExecution.equals(selected),"Startup Last reran Compare instead of selected leaf");check(AndroidMultihopController.capturedInputs&&AndroidMultihopController.lastPins.equals(historical.serverIdentityPins),"historical graph lost exact source or public pins");
    check(f.runtime.activeExecution().equals("auto")&&f.runtime.activeSelectedExecution().equals(selected),"saved preference and selected execution were conflated");check(f.engine.starts==1&&LayeredVpnService.nativeGeneration==generation+1&&f.engine.leases==(selected.equals("server")?1:0)&&AndroidPathProbe.proofs==1,"history reused a native owner, lease or proof");
    check(AndroidStartupPolicy.prepares==0&&AndroidStartupPolicy.writes==0,"Startup Last overwrote history");check(LayeredVpnService.mtu==1,"historical startup missed final activation");
    AndroidMultihopRuntime.RestoreCapture live=f.runtime.captureRestore(f.entry,f.exit,AndroidHomeStateStore.current);check(live.selected.equals(selected)&&live.policy.equals("auto")&&live.owner.serverIdentityPins.equals(historical.serverIdentityPins),"fresh path lost runtime-only restore capture");cases++;
   }
  }
 }
 static void malformed()throws Exception{
  try(Fixture f=new Fixture()){
   for(String selected:new String[]{"auto","","server-extra"})rejected("selected-"+selected,()->AndroidMultihopRuntime.startupCapture(f.entry,f.exit,"wg","auto","wg",selected,"{}",f.a,f.b));
   for(String policy:new String[]{"none","LOCAL",""})rejected("policy-"+policy,()->AndroidMultihopRuntime.startupCapture(f.entry,f.exit,"wg",policy,"wg","local","{}",f.a,f.b));
   rejected("contradictory leaf",()->f.capture("wg","wg","local","server"));rejected("unknown entry",()->f.capture("unknown","wg","auto","local"));rejected("empty exit",()->f.capture("wg","","auto","local"));
   rejected("duplicate node",()->AndroidMultihopRuntime.startupCapture(f.entry,f.entry,"wg","auto","wg","local","{}",f.a,f.a));
   rejected("same file",()->AndroidMultihopRuntime.startupCapture(f.entry,new AndroidNodeStore.Node("foreign",f.entry.file),"wg","auto","wg","local","{}",f.a,f.a));
   rejected("swapped source",()->AndroidMultihopRuntime.startupCapture(f.entry,f.exit,"wg","auto","wg","local","{}",f.b,f.a));
   rejected("null source",()->AndroidMultihopController.captureSource(f.entry.file,null));rejected("empty source",()->AndroidMultihopController.captureSource(f.entry.file,new byte[0]));rejected("oversized source",()->AndroidMultihopController.captureSource(f.entry.file,new byte[32*1024*1024+1]));
   for(String invalid:new String[]{"{}","{\"expected_packet_public_key\":null}","{\"expected_packet_public_key\":\"bad\"}",new JSONObject().put("expected_packet_public_key",publicKey(0)).toString(),new JSONObject().put("expected_packet_public_key",publicKey(9)).put("private_key","secret").toString(),new JSONObject().put("lease_token","secret").toString()})
    rejected("packet pins",()->AndroidMultihopRuntime.startupCapture(f.entry,f.exit,"wg","auto","wg","server",invalid,f.a,f.b));
   for(String invalid:new String[]{"{}",new JSONObject().put("expected_packet_public_key",publicKey(9)).toString(),new JSONObject(pins("server","wg-pq")).put("expected_pq_client_identity","0".repeat(64)).toString(),new JSONObject(pins("server","wg-pq")).put("expected_pq_client_identity","AB".repeat(32)).toString(),new JSONObject(pins("server","wg-pq")).put("score",1).toString()})
    rejected("PQ pins",()->AndroidMultihopRuntime.startupCapture(f.entry,f.exit,"wg-pq","auto","wg","server",invalid,f.a,f.b));
   rejected("Local with Server authority",()->AndroidMultihopRuntime.startupCapture(f.entry,f.exit,"wg","auto","wg","local",pins("server","wg"),f.a,f.b));
   for(String invalid:new String[]{" { } ","{\"expected_packet_public_key\":\""+publicKey(9)+"\",\"expected_packet_public_key\":\""+publicKey(9)+"\"}"})
    rejected("ambiguous raw pin object",()->AndroidMultihopRuntime.startupCapture(f.entry,f.exit,"wg","auto","wg",invalid.contains("expected")?"server":"local",invalid,f.a,f.b));
   byte[] mutable=f.a.clone();AndroidMultihopRuntime.StartupCapture capture=AndroidMultihopRuntime.startupCapture(f.entry,f.exit,"wg","auto","wg","local","{}",mutable,f.b);Arrays.fill(mutable,(byte)0);capture.require(f.entry,f.exit);check(!capture.entrySource.digest.equals(new String(mutable,StandardCharsets.UTF_8)),"capture retained mutable credentials");
   Files.writeString(f.entry.file.toPath(),"{}");rejected("invalid current bundle",()->AndroidMultihopController.captureSource(f.entry.file,"{}".getBytes(StandardCharsets.UTF_8)));Files.write(f.entry.file.toPath(),f.a);
  }
 }
 static void staleAndProof()throws Exception{
  for(boolean first:new boolean[]{true,false})try(Fixture f=new Fixture()){AndroidMultihopRuntime.StartupCapture capture=f.capture("wg","wg","auto","local");f.change(first);Callback c=f.last(capture);c.await();check(!c.ok&&f.engine.starts==0,"stale historical source launched native graph");cases++;}
  try(Fixture f=new Fixture()){AndroidMultihopRuntime.StartupCapture capture=f.capture("wg","wg","auto","local");AndroidHomeStateStore.Snapshot idle=AndroidHomeStateStore.current;AndroidHomeStateStore.current=new AndroidHomeStateStore.Snapshot();AndroidHomeStateStore.current.sessionId="replacement";Callback c=new Callback();f.runtime.connectLast(f.entry,f.exit,capture,idle,c);c.await();check(!c.ok&&f.engine.starts==0&&AndroidHomeStateStore.current.sessionId.equals("replacement"),"historical request replaced a newer Home owner");cases++;}
  for(String fault:new String[]{"entry","exit","cancel"})try(Fixture f=new Fixture()){
   AndroidMultihopRuntime.StartupCapture capture=f.capture("wg","wg","auto","local");Field field=AndroidMultihopRuntime.class.getDeclaredField("executor");field.setAccessible(true);ExecutorService worker=(ExecutorService)field.get(f.runtime);CountDownLatch entered=new CountDownLatch(1),release=new CountDownLatch(1);
   worker.submit(()->{entered.countDown();try{release.await();}catch(InterruptedException e){Thread.currentThread().interrupt();}});check(entered.await(3,TimeUnit.SECONDS),"queued worker did not block");Callback c;
   try{c=f.last(capture);if(fault.equals("cancel"))f.runtime.disconnect();else f.change(fault.equals("entry"));}finally{release.countDown();}c.await();check(!c.ok&&f.engine.starts==0,"queued Last bypassed current source or cancellation");cases++;
  }
  for(String fault:new String[]{"entry","exit","private-proof","native-proof","selected","pins","generation","source-during-capture","native-owner-during-capture","native-pins-during-capture"})try(Fixture f=new Fixture()){
   AndroidMultihopRuntime.StartupCapture capture=f.capture("wg","wg-pq","auto","server");
   if(fault.equals("entry")||fault.equals("exit"))f.engine.duringStart=()->f.change(fault.equals("entry"));
   if(fault.equals("private-proof"))AndroidPathProbe.valid=false;if(fault.equals("native-proof"))LayeredVpnService.unhealthy=true;
   if(fault.equals("selected"))f.engine.duringStart=()->LayeredVpnService.selected="local";
   if(fault.equals("pins"))f.engine.duringStart=()->{try{LayeredVpnService.pins=new JSONObject(capture.serverIdentityPins).put("expected_packet_public_key",publicKey(10)).toString();}catch(Exception e){throw new AssertionError(e);}};
   if(fault.equals("generation"))LayeredVpnService.wrongGeneration=true;
   if(fault.equals("source-during-capture"))LayeredVpnService.duringCapture=()->f.change(true);
   if(fault.equals("native-owner-during-capture"))LayeredVpnService.duringCapture=()->LayeredVpnService.nativeGeneration++;
   if(fault.equals("native-pins-during-capture"))LayeredVpnService.duringCapture=()->{try{LayeredVpnService.pins=new JSONObject(capture.serverIdentityPins).put("expected_packet_public_key",publicKey(10)).toString();}catch(Exception e){throw new AssertionError(e);}};
   Callback c=f.last(capture);c.await();check(!c.ok&&f.engine.starts==1&&f.engine.stops==1&&!AndroidHomeStateStore.current.connected,"fresh proof/source/identity failure was adopted: "+fault);check(LayeredVpnService.mtu==0&&AndroidStartupPolicy.writes==0,"failed historical path activated or wrote history: "+fault);cases++;
  }
  try(Fixture f=new Fixture()){AndroidMultihopRuntime.StartupCapture capture=f.capture("wg","wg","auto","local");LayeredVpnService.unhealthy=true;f.engine.stopEntered=new CountDownLatch(1);f.engine.stopRelease=new CountDownLatch(1);Callback c=f.last(capture);
   try{check(f.engine.stopEntered.await(3,TimeUnit.SECONDS),"failed owner did not enter cleanup");check(!AndroidHomeStateStore.current.connected&&LayeredVpnService.mtu==0,"provisional Home proof survived failed native capture while stopping");}finally{f.engine.stopRelease.countDown();}c.await();check(!c.ok,"failed native capture delivered success");cases++;
  }
 }
 static void historicalRecording()throws Exception{
  for(String chosen:new String[]{"local","server"})try(Fixture f=new Fixture()){LayeredVpnService.selected=chosen;LayeredVpnService.pins=pins(chosen,"wg-pq");Callback c=new Callback();f.runtime.connect(f.entry,f.exit,"wg-pq","auto","max-quic-awg",c);c.await();check(c.ok&&AndroidStartupPolicy.prepares==1&&AndroidStartupPolicy.writes==1,"proved manual multihop did not record one historical winner");check(AndroidStartupPolicy.selected.equals(chosen)&&AndroidStartupPolicy.pins.equals(LayeredVpnService.pins),"history changed selected leaf or public pins");cases++;}
  try(Fixture f=new Fixture()){Field field=AndroidMultihopRuntime.class.getDeclaredField("executor");field.setAccessible(true);ExecutorService worker=(ExecutorService)field.get(f.runtime);CountDownLatch entered=new CountDownLatch(1),release=new CountDownLatch(1);worker.submit(()->{entered.countDown();try{release.await();}catch(InterruptedException e){Thread.currentThread().interrupt();}});check(entered.await(3,TimeUnit.SECONDS),"temporary queue did not block");Object lease=AndroidMTUMeasurementGate.acquire();Callback c=new Callback();
   try{LayeredVpnService.selected="local";f.runtime.connect(f.entry,f.exit,"wg","auto","wg",c);}finally{AndroidMTUMeasurementGate.release(lease);release.countDown();}c.await();check(c.ok&&AndroidStartupPolicy.prepares==0&&AndroidStartupPolicy.writes==0,"temporary request entered Last history after its lease was released");cases++;}
  for(String fault:new String[]{"entry","exit","cancel"})try(Fixture f=new Fixture()){LayeredVpnService.selected="local";AndroidStartupPolicy.onPrepare=()->{if(fault.equals("cancel"))f.runtime.disconnect();else f.change(fault.equals("entry"));};Callback c=new Callback();f.runtime.connect(f.entry,f.exit,"wg","auto","wg",c);c.await();check(!c.ok&&AndroidStartupPolicy.writes==0&&LayeredVpnService.mtu==0,"late private-store preparation blessed cancelled or changed path");cases++;}
  for(boolean nativeOwner:new boolean[]{true,false})try(Fixture f=new Fixture()){LayeredVpnService.selected="local";LayeredVpnService.duringCapture=()->{if(nativeOwner)LayeredVpnService.nativeGeneration++;else f.change(true);};Callback c=new Callback();f.runtime.connect(f.entry,f.exit,"wg","auto","wg",c);c.await();check(!c.ok&&AndroidStartupPolicy.writes==0&&LayeredVpnService.mtu==0,"unretained native capture wrote historical execution");cases++;}
  for(String fault:new String[]{"native-proof","native-owner","home-generation","home-replacement","entry","exit","native-owner-during-mtu"})try(Fixture f=new Fixture()){
   LayeredVpnService.selected="local";
   AndroidStartupPolicy.onRecord=()->{if(fault.equals("native-proof"))LayeredVpnService.unhealthy=true;if(fault.equals("native-owner"))LayeredVpnService.nativeGeneration++;if(fault.equals("home-generation"))AndroidHomeStateStore.current.pathGeneration++;
    if(fault.equals("home-replacement")){AndroidHomeStateStore.Snapshot next=new AndroidHomeStateStore.Snapshot();next.sessionId="replacement-home";next.phase="replacement";AndroidHomeStateStore.current=next;}
    if(fault.equals("entry")||fault.equals("exit"))f.change(fault.equals("entry"));
    if(fault.equals("native-owner-during-mtu"))LayeredVpnService.duringMTU=()->LayeredVpnService.nativeGeneration++;
   };
   Callback c=new Callback();f.runtime.connect(f.entry,f.exit,"wg","auto","wg",c);c.await();check(!c.ok&&LayeredVpnService.mtu==0&&!AndroidHomeStateStore.current.connected,"durable-record interval escaped captured native/source ownership: "+fault);
   if(fault.equals("home-replacement"))check(AndroidHomeStateStore.current.sessionId.equals("replacement-home")&&AndroidHomeStateStore.current.phase.equals("replacement"),"old record cleanup rewrote replacement Home");cases++;
  }
  try(Fixture f=new Fixture()){LayeredVpnService.selected="local";AndroidStartupPolicy.writeFailure=true;Callback c=new Callback();f.runtime.connect(f.entry,f.exit,"wg","auto","wg",c);c.await();check(c.ok&&AndroidStartupPolicy.writes==0&&LayeredVpnService.mtu==1,"harmless historical write failure disconnected proved path");cases++;}
 }
 public static void main(String[] args)throws Exception{importedRuntime();historicalMatrix();malformed();staleAndProof();historicalRecording();System.out.println("Android two-Router historical execution: "+checks+" checks / "+cases+" cases; actual runtime, source files and public-pin constraints");}
}
'''


def main():
    jar = Path(os.environ.get('ANDROID_JSON_JAR', '/usr/share/java/com.android.json.jar'))
    if not jar.is_file():
        raise RuntimeError('Actual Android JSON library required')
    controller = (JAVA / 'AndroidMultihopController.java').read_text()
    native = (JAVA / 'NativeSingBoxController.java').read_text()
    source_members = '\n'.join(member(controller, marker) for marker in (
        '    static final class Source {', '    private static final class LoadedBundle {',
        '    static Source captureSource(', '    static String validatedServerIdentityPins(',
        '    private static String sourceDigest(', '    private static byte[] readBundleBytes('))
    predicates = '\n'.join(member(native, '    static boolean ' + name + '(') for name in
                           ('nativeWireGuardFamily', 'nativePQFamily', 'nativeNaiveFamily', 'nativeMultihopEntry'))
    max_source = (JAVA / 'AndroidNativeMAXProfile.java').read_text()
    max_modes = re.search(r'(?s)    private static final (?:java\.util\.)?Set<String> MODES\s*=.*?;', max_source)
    assert max_modes, 'missing actual MAX transport set'
    max_predicate = max_modes[0] + '\n' + member(max_source, '    static boolean isMode(')
    composite_predicate = member((JAVA / 'AndroidNativeCompositeProfile.java').read_text(), '    static boolean isMode(')
    stubs = STUBS.replace('// REAL_SOURCE_MEMBERS', source_members).replace('// NATIVE_PREDICATES', predicates)
    stubs = stubs.replace('// MAX_PREDICATE', max_predicate).replace('// COMPOSITE_PREDICATE', composite_predicate)
    stubs = stubs.replace('// SHIPPING_IMPORTED_SUPPORTS', member((JAVA/'AndroidImportedRouterPath.java').read_text(), '    static boolean supports('))
    with tempfile.TemporaryDirectory(prefix='routervpn-multihop-startup-last-') as directory:
        root = Path(directory)
        app = root / 'com/eabusham/routervpn'
        app.mkdir(parents=True)
        target = app / 'AndroidMultihopRuntime.java'
        shutil.copyfile(JAVA / target.name, target)
        shutil.copyfile(JAVA / 'AndroidMTUMeasurementGate.java', app / 'AndroidMTUMeasurementGate.java')
        boundary = app / 'HistoricalBoundaries.java'
        boundary.write_text(stubs)
        (app / 'MultihopStartupLastTest.java').write_text(HARNESS)
        context = root / 'android/content/Context.java'
        context.parent.mkdir(parents=True)
        context.write_text('package android.content;public class Context{public Context getApplicationContext(){return this;}}')
        base64 = root / 'android/util/Base64.java'
        base64.parent.mkdir(parents=True)
        base64.write_text('package android.util;public class Base64{public static final int DEFAULT=0,NO_WRAP=2;public static byte[] decode(String s,int f){return java.util.Base64.getMimeDecoder().decode(s);}public static String encodeToString(byte[] b,int f){return java.util.Base64.getEncoder().encodeToString(b);}}')
        classes = root / 'classes'
        compile = ['javac', '--release', '17', '-encoding', 'UTF-8', '-cp', str(jar), '-d', str(classes), *map(str, root.rglob('*.java'))]
        run = ['java', '-cp', os.pathsep.join((str(classes), str(jar))), 'com.eabusham.routervpn.MultihopStartupLastTest']
        subprocess.run(compile, check=True, timeout=45)
        subprocess.run(run, check=True, timeout=45)
        original = target.read_text()
        controls = (
            ('published SOCKS admission', target, 'imported ? !AndroidImportedRouterPath.supports(entryMode,exitMode)', 'imported ? !java.util.Arrays.asList("shadowsocks","hysteria2","wireguard","amneziawg").contains(entryMode)', 'supported SOCKS imported runtime rejected before preparation'),
            ('historical leaf', target, 'connectCaptured(entry,exit,capture.exitMode,capture.selected,capture.policy,capture.entryMode,', 'connectCaptured(entry,exit,capture.exitMode,capture.policy,capture.policy,capture.entryMode,', 'valid historical choice failed'),
            ('historical no-write', target, 'capture.entrySource,capture.exitSource,capture.serverIdentityPins,idle,false,callback);', 'capture.entrySource,capture.exitSource,capture.serverIdentityPins,idle,true,callback);', 'Startup Last overwrote history'),
            ('submission-time temporary ownership', target, 'boolean remember=!AndroidMTUMeasurementGate.held();', 'boolean remember=true;', 'temporary request entered Last history'),
            ('actual winner publication', target, 'AndroidStartupPolicy.recordMultihopExecution(context,last,adopted,proved.execution,pins);', '/* mutation: missing actual winner publication */', 'proved manual multihop did not record'),
            ('server identity readback', target, 'if(expectedPins!=null&&!expectedPins.equals(pins))', 'if(false)', 'fresh proof/source/identity failure was adopted: pins'),
            ('native path generation', target, 'if(!proved.matchesHome(adopted)||!homeSession.equals(proved.homeSession)', 'if(!homeSession.equals(proved.homeSession)', 'fresh proof/source/identity failure was adopted: generation'),
            ('source during native capture', target, 'prepared.entrySource.require(entryFile);prepared.exitSource.require(exit.file);\n                    if(!proved.sameOwner(LayeredVpnService.capturedMultihop(homeSession)))throw new IllegalStateException("The native multihop owner changed during source validation.");', 'if(!proved.sameOwner(LayeredVpnService.capturedMultihop(homeSession)))throw new IllegalStateException("The native multihop owner changed during source validation.");', 'unretained native capture wrote historical execution'),
            ('native owner after source validation', target, 'if(!proved.sameOwner(LayeredVpnService.capturedMultihop(homeSession)))throw new IllegalStateException("The native multihop owner changed during source validation.");', '/* mutation: native owner not revalidated before historical write */', 'unretained native capture wrote historical execution'),
            ('source after durable write', target, 'prepared.entrySource.require(entryFile);prepared.exitSource.require(exit.file);\n                    if(!proved.sameOwner(LayeredVpnService.capturedMultihop(homeSession)))throw new IllegalStateException("The native multihop owner changed while recording Startup Last.");', 'if(!proved.sameOwner(LayeredVpnService.capturedMultihop(homeSession)))throw new IllegalStateException("The native multihop owner changed while recording Startup Last.");', 'durable-record interval escaped captured native/source ownership: entry'),
            ('captured MTU activation', target, 'LayeredVpnService.startMultihopAutomaticMTU(proved);', 'LayeredVpnService.startAutomaticMTU();', 'durable-record interval escaped captured native/source ownership: native-owner-during-mtu'),
            ('provisional proof retirement', target, 'AndroidHomeStateStore.beginPathRevalidation(context,"The captured multihop proof changed before activation.");', ';', 'provisional Home proof survived failed native capture'),
            ('current raw source identity', boundary, 'if (!current.source.digest.equals(sourceDigest(expectedBytes)))', 'if (false)', 'invalid historical capture accepted: swapped source'),
            ('canonical public constraints', target, 'if(!canonicalPins.equals(pins))', 'if(false)', 'invalid historical capture accepted: ambiguous raw pin object'),
        )
        for label, file, before, after, expected in controls:
            source = original if file == target else stubs
            assert source.count(before) == 1, (label, 'mutation anchor drift')
            file.write_text(source.replace(before, after))
            subprocess.run(compile, check=True, timeout=45, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            result = subprocess.run(run, capture_output=True, text=True, timeout=45)
            file.write_text(source)
            assert result.returncode and 'AssertionError' in result.stderr and expected in result.stdout + result.stderr, (label, 'did not fail at intended runtime assertion', result.stdout, result.stderr)
            print('Android two-Router Last mutation rejected:', label)
        print('Android historical multihop runtime: fourteen source/owner/public-identity mutations rejected')



COMPOSED = r'''package com.eabusham.routervpn;
import android.content.Context;import java.nio.file.*;import java.util.*;import java.util.concurrent.*;import org.json.*;
public final class ComposedTest {
 static Context context;static int checks;
 static void check(boolean ok,String message){checks++;if(!ok)throw new AssertionError(message);}
 static final class Callback implements AndroidMultihopRuntime.Callback {final CountDownLatch done=new CountDownLatch(1);boolean ok;int completions;public void progress(String s){}public void finished(boolean value,String message){ok=value;completions++;done.countDown();}void await()throws Exception{check(done.await(4,TimeUnit.SECONDS)&&completions==1,"composed runtime did not finish one owned callback");}}
 static byte[] source()throws Exception{return new JSONObject().put("node_id","final").put("profiles",new JSONObject()).put("modes",new JSONArray()).toString().getBytes(java.nio.charset.StandardCharsets.UTF_8);}
 public static void main(String[] args)throws Exception{
  for(String protocol:List.of("socks5","http","https"))for(String mode:protocol.equals("socks5")?List.of("shadowsocks","hysteria2","wg","awg2-fast","awg2-strong"):List.of("shadowsocks"))for(String fault:List.of("none","source-before-stage","source-after-start","proof","cancel")){
   context=new Context();NativeSingBoxController engine=new NativeSingBoxController();AndroidMultihopController.preparations=0;AndroidMultihopController.onPrepare=null;AndroidPathProbe.proofs=0;AndroidPathProbe.valid=!fault.equals("proof");AndroidPathProbe.duringProof=null;
   LayeredVpnService.captures=0;LayeredVpnService.mtu=0;LayeredVpnService.unhealthy=false;LayeredVpnService.selected="";LayeredVpnService.pins="{}";LayeredVpnService.duringCapture=null;LayeredVpnService.duringMTU=null;
   Path directory=Files.createTempDirectory("composed-imported-home-"),file=directory.resolve("final.json");Files.write(file,source());AndroidNodeStore.Node last=new AndroidNodeStore.Node("final",file.toFile());
   AndroidStandardExitStore.Entry first=new AndroidStandardExitStore.Entry();first.id="original-socks";first.name="Saved SOCKS";first.protocol=protocol;AndroidImportedRouterPath.current=first;
   AndroidMultihopRuntime runtime=new AndroidMultihopRuntime(context,engine);AndroidStartupPolicy.runtime=runtime;
   try{
    if(fault.equals("source-before-stage"))AndroidMultihopController.onPrepare=()->first.secret="changed original source";
    if(fault.equals("source-after-start"))engine.duringStart=()->first.secret="changed original source";
    if(fault.equals("cancel"))AndroidMultihopController.onPrepare=runtime::disconnect;
    Callback callback=new Callback();runtime.connectImported(first,last,mode,"local",callback);callback.await();
    AndroidHomeStateStore.Snapshot home=AndroidHomeStateStore.snapshot(context);
    if(fault.equals("none")){
     check(callback.ok&&engine.starts==1&&AndroidMultihopController.preparations==1,"composed SOCKS runtime/Home rejected published path: "+mode);
     check(home.connected&&home.pathProof.equals("passed")&&home.activeEntryId.equals(first.id)&&home.activeExitId.equals(last.id)&&home.activeEntryMode.equals(AndroidExternalPolicy.protocol(protocol))&&home.runtimeMode.equals(mode)&&home.actualBase.equals("libbox"),"composed runtime adopted wrong real Home identity");
     check(LayeredVpnService.captures>0&&LayeredVpnService.mtu==1,"composed runtime activated before owned proof");
    }else check(!callback.ok&&!home.connected&&LayeredVpnService.mtu==0,"composed runtime published cancelled/stale/unproved Home: "+fault);
   }finally{runtime.disconnect();runtime.close();long end=System.nanoTime()+TimeUnit.SECONDS.toNanos(3);while(runtime.isActiveOrTransitioning()&&System.nanoTime()<end)Thread.yield();check(!AndroidHomeStateStore.snapshot(context).connected&&engine.state.equals("DOWN"),"composed cleanup retained live Home or native owner: "+fault+"/"+engine.state+"/"+AndroidHomeStateStore.snapshot(context).phase);Files.delete(file);Files.delete(directory);}
  }
  for(String protocol:List.of("socks5","http","https"))for(String mode:protocol.equals("socks5")?List.of("shadowsocks","hysteria2","wg","awg2-fast","awg2-strong"):List.of("shadowsocks"))for(boolean alive:List.of(false,true)){
   context=new Context();AndroidHomeStateStore.beginMultihop(context,"saved-socks","saved-final",mode,AndroidExternalPolicy.protocol(protocol));AndroidHomeStateStore.connectedMultihop(context,"saved-socks","saved-final",mode,AndroidExternalPolicy.protocol(protocol));
   NativeSingBoxController engine=new NativeSingBoxController();engine.state=alive?"UP":"DOWN";AndroidMultihopRuntime runtime=new AndroidMultihopRuntime(context,engine);
   try{check(runtime.isConnected()==alive&&AndroidHomeStateStore.snapshot(context).connected==alive,"published SOCKS live-state reattachment changed exact native liveness");if(alive)check(runtime.activeEntryMode().equals(AndroidExternalPolicy.protocol(protocol)),"reattachment changed original entry label");}
   finally{runtime.disconnect();runtime.close();}
  }
  System.out.println("Composed shipping imported runtime + Home: "+checks+" checks /49 cases PASS; native preparation/proof and Android OS boundaries doubled");
 }
}
'''


def composed_home():
    import importlib.util
    spec = importlib.util.spec_from_file_location('composed_home_boundary', ROOT/'android/test_android_multihop_home_state.py')
    home_fixture = importlib.util.module_from_spec(spec); spec.loader.exec_module(home_fixture)
    controller = (JAVA/'AndroidMultihopController.java').read_text()
    source_members = '\n'.join(member(controller, marker) for marker in (
        '    static final class Source {', '    private static final class LoadedBundle {',
        '    static Source captureSource(', '    static String validatedServerIdentityPins(',
        '    private static String sourceDigest(', '    private static byte[] readBundleBytes('))
    native = (JAVA/'NativeSingBoxController.java').read_text()
    predicates = '\n'.join(member(native, '    static boolean '+name+'(') for name in ('nativeWireGuardFamily','nativePQFamily','nativeNaiveFamily','nativeMultihopEntry'))
    maximum = (JAVA/'AndroidNativeMAXProfile.java').read_text()
    modes = re.search(r'(?s)    private static final (?:java\.util\.)?Set<String> MODES\s*=.*?;',maximum)[0]
    stubs = STUBS.replace(member(STUBS,'final class AndroidHomeStateStore {'),'')
    stubs = stubs.replace(member(stubs,'final class AndroidExternalPolicy {'),'')
    stubs = stubs.replace('// REAL_SOURCE_MEMBERS',source_members).replace('// NATIVE_PREDICATES',predicates)
    stubs = stubs.replace('// MAX_PREDICATE',modes+'\n'+member(maximum,'    static boolean isMode(')).replace('// COMPOSITE_PREDICATE',member((JAVA/'AndroidNativeCompositeProfile.java').read_text(),'    static boolean isMode('))
    stubs = stubs.replace('// SHIPPING_IMPORTED_SUPPORTS',member((JAVA/'AndroidImportedRouterPath.java').read_text(),'    static boolean supports('))
    stubs = stubs.replace('AndroidHomeStateStore.current','AndroidHomeStateStore.snapshot(ComposedTest.context)')
    with tempfile.TemporaryDirectory(prefix='routervpn-composed-imported-home-') as directory:
        root=Path(directory);app=root/'com/eabusham/routervpn';app.mkdir(parents=True)
        for name in ('AndroidMultihopRuntime','AndroidHomeStateStore','AndroidMTUMeasurementGate'):
            shutil.copyfile(JAVA/(name+'.java'),app/(name+'.java'))
        (app/'Boundaries.java').write_text(stubs)
        (app/'ComposedTest.java').write_text(COMPOSED)
        for name in ('android/content/SharedPreferences.java','android/content/Context.java','com/wireguard/android/backend/Tunnel.java','org/amnezia/awg/backend/Tunnel.java','com/eabusham/routervpn/HomeBoundaries.java'):
            target=root/name;target.parent.mkdir(parents=True,exist_ok=True)
            source=home_fixture.SOURCES[name]
            if name.endswith('HomeBoundaries.java'):
                external=(JAVA/'AndroidExternalPolicy.java').read_text()
                source=source.replace('// SHIPPING_EXTERNAL_POLICY_MEMBERS',member(external,'    static boolean supports(')+'\n'+member(external,'    static String protocol('))
            target.write_text(source)
        target=root/'android/content/Intent.java';target.write_text('package android.content;public class Intent{}')
        target=root/'android/util/Base64.java';target.parent.mkdir(parents=True)
        target.write_text('package android.util;public class Base64{public static final int DEFAULT=0,NO_WRAP=2;public static byte[] decode(String s,int f){return java.util.Base64.getMimeDecoder().decode(s);}public static String encodeToString(byte[] b,int f){return java.util.Base64.getEncoder().encodeToString(b);}}')
        jar=Path(os.environ.get('ANDROID_JSON_JAR','/usr/share/java/com.android.json.jar'));classes=root/'classes'
        compile=['javac','--release','17','-encoding','UTF-8','-cp',str(jar),'-d',str(classes),*map(str,root.rglob('*.java'))]
        run=['java','-cp',os.pathsep.join((str(classes),str(jar))),'com.eabusham.routervpn.ComposedTest']
        subprocess.run(compile,check=True,timeout=45);subprocess.run(run,check=True,timeout=45)
        for name,old,new in (
            ('AndroidMultihopRuntime.java','return AndroidExternalPolicy.protocol(entry.protocol);','return entry.protocol;'),
            ('AndroidMultihopRuntime.java','imported ? !AndroidImportedRouterPath.supports(entryMode,exitMode)','imported ? !java.util.Arrays.asList("shadowsocks","hysteria2","wireguard","amneziawg").contains(entryMode)'),
            ('AndroidMultihopRuntime.java','AndroidImportedRouterPath.supports(state.activeEntryMode,state.runtimeMode)','java.util.Arrays.asList("wireguard","amneziawg").contains(state.activeEntryMode)'),
            ('AndroidHomeStateStore.java','!AndroidImportedRouterPath.supports(entryMode,runtimeMode)','!java.util.Arrays.asList("wireguard","amneziawg").contains(entryMode)')):
            target=app/name;original=target.read_text();assert old in original;target.write_text(original.replace(old,new))
            subprocess.run(compile,check=True,timeout=45,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            result=subprocess.run(run,capture_output=True,text=True,timeout=45);target.write_text(original)
            witnesses = ('composed runtime adopted wrong real Home identity',) if old=='return AndroidExternalPolicy.protocol(entry.protocol);' else ('composed SOCKS runtime/Home rejected published path','Invalid live entry transport','published SOCKS live-state reattachment changed exact native liveness')
            if not result.returncode or not any(w in result.stderr for w in witnesses):
                raise AssertionError('Composed old admission did not fail at exact boundary: '+name+'\n'+result.stdout+result.stderr)
            print('Composed actual runtime/Home old admission rejected:',name)


if __name__ == '__main__':
    main()
    composed_home()
