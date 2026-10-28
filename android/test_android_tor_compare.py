#!/usr/bin/env python3
"""Execute the shipping Android Tor comparison host and service ownership.

The native Go coordinator, Android platform and engines are explicit boundary
fixtures here. Scoring/native sockets are covered by the actual Go/native gates;
this gate exercises the Java owner, late callbacks and real service teardown.
"""
from pathlib import Path
import importlib.util
import contextlib
import io
import shutil
import subprocess
import sys
import tempfile

ROOT=Path(__file__).resolve().parents[1]
JAVA=ROOT/'android/app/src/main/java/com/eabusham/routervpn'

HOST_STUBS=r'''package com.eabusham.routervpn;
import java.util.*;import java.util.concurrent.*;import java.util.concurrent.atomic.*;
final class NativeSingBoxController {
 static final class SessionInfo {final String sessionId,modeId;final Preparation maxPreparation;SessionInfo(String id,String mode){sessionId=id;modeId=mode;maxPreparation=new Preparation();}}
 static final class Preparation{boolean closed;void close(){closed=true;}}
}
final class AndroidStandardExitStore{
 static final class Entry{String id="external-tor",protocol="tor",source="private-exit";}
 static Entry copy(Entry x){Entry y=new Entry();y.id=x.id;y.protocol=x.protocol;y.source=x.source;return y;}
 static void validate(Entry e){}static void validateExecution(Entry e,boolean hasEntry,String x){if(!hasEntry&&!x.equals("local"))throw new IllegalArgumentException("private entry required");}
 static String snapshot(Entry x){return x.id+"/"+x.protocol+"/"+x.source;}
}
final class AndroidTorProfile{
 static final AtomicInteger prepares=new AtomicInteger();static volatile CountDownLatch entered,release;static volatile Runnable after;
 static boolean isTor(String x){return x.equals("tor")||x.equals("tor-bridge");}
 static String digest(byte[] bytes)throws Exception{return java.util.HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256").digest(bytes));}
 static NativeSingBoxController.SessionInfo prepare(android.content.Context c,java.io.File f,AndroidStandardExitStore.Entry e,String mode)throws Exception{return prepare(c,f,e,mode,"local");}
 static NativeSingBoxController.SessionInfo prepare(android.content.Context c,java.io.File f,AndroidStandardExitStore.Entry e,String mode,String execution)throws Exception{
  if(!List.of("local","server").contains(execution))throw new AssertionError("auto escaped concrete leaf");
  int n=prepares.incrementAndGet();CountDownLatch in=entered,hold=release;boolean interrupted=false;
  if(in!=null){in.countDown();while(true){try{hold.await();break;}catch(InterruptedException ignored){interrupted=true;}}}
  if(after!=null)after.run();if(interrupted)Thread.currentThread().interrupt();
  return new NativeSingBoxController.SessionInfo(String.format("%032x",n),mode+"-"+execution);
 }
}
final class AndroidExternalPolicy{
 static boolean supports(String p){return false;}
 static NativeSingBoxController.SessionInfo prepare(android.content.Context c,java.io.File f,AndroidStandardExitStore.Entry e,String mode){throw new AssertionError("wrong compiler");}
 static NativeSingBoxController.SessionInfo prepare(android.content.Context c,java.io.File f,AndroidStandardExitStore.Entry e,String mode,String x,String y){throw new AssertionError("wrong compiler");}
}
final class AndroidMAXDNSOwner{
 static volatile int network=1;static volatile boolean physical=true;
 static final class Physical{final int generation=network;final String digest="physical-"+generation;Physical(android.content.Context c){}boolean current(boolean vpn){return generation==network&&(vpn||physical);}}
}
final class LayeredVpnService{
 static final AtomicInteger discards=new AtomicInteger(),closes=new AtomicInteger();static volatile boolean failClose,delayLaunch;static volatile TorCompareTrial reserved,last;
 static boolean discardPreparedSession(android.content.Context c,String id){discards.incrementAndGet();return true;}
 interface TorCompareCurrent{boolean current();}
 static final class TorCompareTrial{
  final NativeSingBoxController.SessionInfo session;final String execution;final TorCompareCurrent owner;final io.nekohasekai.libbox.CommandServer server=new io.nekohasekai.libbox.CommandServer();final io.nekohasekai.libbox.RouterTorProofRequest proof=new io.nekohasekai.libbox.RouterTorProofRequest();boolean submitted;volatile boolean up,cancelled,closed,kept;
  TorCompareTrial(NativeSingBoxController.SessionInfo s,String x,TorCompareCurrent o){session=s;execution=x;owner=o;}
  static synchronized TorCompareTrial reserve(NativeSingBoxController.SessionInfo s,String e,String x,AndroidMAXDNSOwner.Physical p,TorCompareCurrent o){if(reserved!=null&&!reserved.closed)throw new IllegalStateException("old trial retained");reserved=new TorCompareTrial(s,x,o);last=reserved;return reserved;}
  void submit(){if(cancelled||closed)throw new IllegalStateException("cancelled");submitted=true;}
  synchronized void activate(){if(!submitted||cancelled||closed)return;up=true;AndroidMAXDNSOwner.physical=false;}
  String failure(){return closed?"closed":"";}
  boolean current(){return up&&!closed&&!cancelled&&owner.current();}
  io.nekohasekai.libbox.CommandServer server(){return current()?server:null;}
  io.nekohasekai.libbox.RouterTorProofRequest proof(){return current()?proof:null;}
  synchronized void cancel(){if(!kept)cancelled=true;}
  synchronized void close(){if(kept||closed)return;cancelled=true;if(failClose)throw new IllegalStateException("native close held");up=false;closed=true;closes.incrementAndGet();if(reserved==this)reserved=null;AndroidMAXDNSOwner.physical=true;}
  synchronized void keep(){if(!current())throw new IllegalStateException("stale winner");kept=true;if(reserved==this)reserved=null;}
 }
}
'''
GO_ROUND=r'''package io.nekohasekai.libbox;
import java.util.*;import java.util.concurrent.*;
/** Explicit coordinator boundary: Java host ownership, not network timing. */
public final class RouterTorCompare{
 public static volatile String winner="server",transport="";public static volatile boolean failFactory,fallback;public static volatile CountDownLatch keeping,keepRelease;
 public static final List<String> opened=Collections.synchronizedList(new ArrayList<>());public static final List<String> targets=Collections.synchronizedList(new ArrayList<>());
 public static volatile RouterTorCompare last;public final RouterTorCompareHost host;private volatile RouterTorCompareCandidate active;private volatile boolean cancelled,kept;
 public RouterTorCompare(RouterTorCompareHost h){host=h;last=this;}
 private void open(String execution)throws Exception{if(cancelled||!host.current())throw new Exception("cancelled");String target="https://1.0.0.1/cdn-cgi/trace";active=host.newCandidate(execution,target);if(active==null)throw new Exception("candidate unavailable");opened.add(execution);targets.add(target);active.start();if(!active.current()||active.server()==null||active.proof()==null)throw new Exception("actual host did not retain proof");host.progress("probing",execution);}
 public void run()throws Exception{for(String x:List.of("local","server")){open(x);active.cancel();active.close();}if(fallback){open("local");active.cancel();active.close();host.progress("activation-failed","local");}open(winner);host.progress("selected",winner);}
 public String execution(){return winner;}
 public String resultJSON(){return "{}";}
 public void keep()throws Exception{CountDownLatch entered=keeping,release=keepRelease;if(entered!=null){entered.countDown();release.await();}synchronized(this){if(cancelled||!host.current()||!active.current())throw new Exception("stale transfer");kept=true;}}
 public void cancel(){RouterTorCompareCandidate c;synchronized(this){if(kept)return;cancelled=true;c=active;}if(c!=null)c.cancel();}
 public void close()throws Exception{RouterTorCompareCandidate c;synchronized(this){if(kept)return;cancelled=true;c=active;}if(c!=null)c.close();}
}
'''
HOST_HARNESS=r'''package com.eabusham.routervpn;
import java.io.*;import java.util.*;import java.util.concurrent.*;import java.util.concurrent.atomic.*;
import io.nekohasekai.libbox.*;
public final class TorCompareHarness{
 static int checks;static void check(boolean c,String m){checks++;if(!c)throw new AssertionError(m);}
 static void waitFor(java.util.function.BooleanSupplier ready,String m)throws Exception{long end=System.nanoTime()+3_000_000_000L;while(!ready.getAsBoolean()){if(System.nanoTime()>end)throw new AssertionError(m);Thread.sleep(2);}}
 static final class Owner implements AndroidTorCompareRuntime.Owner{
  volatile boolean alive=true,source=true;final AtomicInteger launches=new AtomicInteger();final List<String> progress=new CopyOnWriteArrayList<>();
  public boolean current(){return alive;}
  public void requireSource(){if(!alive||!source)throw new IllegalStateException("source changed");}
  public void launch(NativeSingBoxController.SessionInfo s){launches.incrementAndGet();if(!LayeredVpnService.delayLaunch)LayeredVpnService.reserved.activate();}
  public void progress(String x){progress.add(x);}
 }
 // Each case represents a fresh executor operation; the preceding source
 // watcher may legitimately leave its synchronous test runner interrupted.
 static void reset(){Thread.interrupted();AndroidTorProfile.prepares.set(0);AndroidTorProfile.entered=null;AndroidTorProfile.release=null;AndroidTorProfile.after=null;AndroidMAXDNSOwner.network=1;AndroidMAXDNSOwner.physical=true;LayeredVpnService.reserved=null;LayeredVpnService.last=null;LayeredVpnService.failClose=false;LayeredVpnService.delayLaunch=false;LayeredVpnService.closes.set(0);LayeredVpnService.discards.set(0);RouterTorCompare.opened.clear();RouterTorCompare.targets.clear();RouterTorCompare.winner="server";RouterTorCompare.transport="";RouterTorCompare.failFactory=false;RouterTorCompare.fallback=false;RouterTorCompare.keeping=null;RouterTorCompare.keepRelease=null;}
 static AndroidTorCompareRuntime create(Owner o)throws Exception{return new AndroidTorCompareRuntime(new android.content.Context(),new File("a".repeat(32)+".json"),new AndroidStandardExitStore.Entry(),"max-tls-awg","home-owner","source-entry",o);}
 static void close(AndroidTorCompareRuntime h)throws Exception{h.close();}
 static Object retainedRound(AndroidTorCompareRuntime h)throws Exception{var field=AndroidTorCompareRuntime.class.getDeclaredField("round");field.setAccessible(true);return field.get(h);}
 static AtomicReference<Throwable> run(AndroidTorCompareRuntime h,CountDownLatch done){AtomicReference<Throwable> failure=new AtomicReference<>();new Thread(()->{try{h.run();}catch(Throwable e){failure.set(e);}finally{done.countDown();}},"host-run").start();return failure;}
 public static void main(String[] args)throws Exception{
  Thread.setDefaultUncaughtExceptionHandler((thread,error)->{error.printStackTrace();System.exit(1);});
  for(String execution:List.of("local","server")){reset();RouterTorCompare.winner=execution;Owner o=new Owner();AndroidTorCompareRuntime h=create(o);NativeSingBoxController.SessionInfo result=h.run();check(RouterTorCompare.opened.equals(List.of("local","server",execution)),"did not run concrete trials and fresh winner");check(new HashSet<>(RouterTorCompare.targets).size()==1,"changed shared target");check(RouterTorCompare.transport.equals("tor"),"candidate transport borrowed entry mode");check(result.modeId.endsWith(execution)&&LayeredVpnService.last.kept&&LayeredVpnService.last.up,"lost exact retained winner");check(retainedRound(h)==null,"successful transfer retained cross-language round cycle");check(LayeredVpnService.closes.get()==2&&LayeredVpnService.discards.get()==2,"trial native/file ownership not drained");h.cancel();h.close();check(LayeredVpnService.last.up&&LayeredVpnService.closes.get()==2,"old round closed adopted path");check(!o.progress.isEmpty()&&o.progress.stream().allMatch(s->s.contains("HTTP")),"ambiguous timing progress");}
  reset();Owner bridgeOwner=new Owner();AndroidStandardExitStore.Entry bridge=new AndroidStandardExitStore.Entry();bridge.protocol="tor-bridge";AndroidTorCompareRuntime bridgeHost=new AndroidTorCompareRuntime(new android.content.Context(),new File("a".repeat(32)+".json"),bridge,"max-quic","home-owner","source-entry",bridgeOwner);bridgeHost.run();check(RouterTorCompare.transport.equals("tor-bridge"),"bridge transport changed in comparison identity");bridgeHost.close();
  reset();RouterTorCompare.fallback=true;Owner fallback=new Owner();AndroidTorCompareRuntime fallbackHost=create(fallback);fallbackHost.run();check(RouterTorCompare.opened.equals(List.of("local","server","local","server"))&&LayeredVpnService.closes.get()==3&&LayeredVpnService.last.kept,"final fallback did not join failed owner before retaining Server");check(fallback.progress.stream().anyMatch(x->x.contains("Local")&&x.contains("no score")),"final failed candidate retained a misleading progress score");fallbackHost.close();
  reset();Owner pinned=new Owner();AndroidTorCompareRuntime pinnedHost=create(pinned);RouterTorCompareCandidate first=pinnedHost.newCandidate("local","https://1.0.0.1/cdn-cgi/trace");check(first!=null,"first approved endpoint rejected");first.close();check(pinnedHost.newCandidate("server","https://1.1.1.1/cdn-cgi/trace")==null,"comparison changed the selected external endpoint");pinnedHost.close();
  reset();AndroidStandardExitController controller=new AndroidStandardExitController(new android.content.Context());File privateEntry=new File("a".repeat(32)+".json");AndroidStandardExitStore.Entry tor=new AndroidStandardExitStore.Entry();
  for(String leaf:List.of("local","server")){NativeSingBoxController.SessionInfo restored=controller.prepare(privateEntry,tor,"max-quic","auto",leaf);check(restored.modeId.equals("max-quic-"+leaf),"restoration reran Compare or changed winner");}
  int before=AndroidTorProfile.prepares.get();for(String[] bad:new String[][]{{"auto",""},{"local","server"},{"server","local"},{"auto","auto"}}){try{controller.prepare(privateEntry,tor,"max-quic",bad[0],bad[1]);throw new AssertionError("invalid restoration leaf admitted");}catch(IllegalArgumentException expected){check(AndroidTorProfile.prepares.get()==before,"invalid restoration reached runtime compiler");}}
  reset();Owner unknown=new Owner();AndroidTorCompareRuntime h=create(unknown);check(h.newCandidate("auto","https://1.0.0.1/cdn-cgi/trace")==null,"auto reached native leaf");check(h.newCandidate("local","https://example.invalid/")==null,"unapproved target admitted");h.close();
  reset();Owner pending=new Owner();AndroidTorProfile.entered=new CountDownLatch(1);AndroidTorProfile.release=new CountDownLatch(1);AndroidTorCompareRuntime hold=create(pending);CountDownLatch done=new CountDownLatch(1);AtomicReference<Throwable> failure=run(hold,done);check(AndroidTorProfile.entered.await(3,TimeUnit.SECONDS),"preparation did not enter");hold.cancel();CountDownLatch closed=new CountDownLatch(1);AtomicReference<Throwable> closeError=new AtomicReference<>();new Thread(()->{try{hold.close();}catch(Throwable e){closeError.set(e);}finally{closed.countDown();}}).start();check(!closed.await(80,TimeUnit.MILLISECONDS),"close falsely joined entered preparation");AndroidTorProfile.release.countDown();check(done.await(3,TimeUnit.SECONDS)&&closed.await(3,TimeUnit.SECONDS),"late preparation did not drain");check(failure.get()!=null&&closeError.get()==null&&pending.launches.get()==0&&LayeredVpnService.discards.get()==1,"late compiled owner launched or leaked");
  reset();Owner changed=new Owner();AndroidTorProfile.after=()->changed.source=false;AndroidTorCompareRuntime stale=create(changed);try{stale.run();throw new AssertionError("changed source admitted");}catch(Exception expected){}stale.close();check(retainedRound(stale)==null,"successful failure cleanup retained cross-language round cycle");check(changed.launches.get()==0&&LayeredVpnService.discards.get()==1,"source swap was not cleaned before launch");
  reset();Owner delayed=new Owner();LayeredVpnService.delayLaunch=true;AndroidTorCompareRuntime late=create(delayed);done=new CountDownLatch(1);failure=run(late,done);waitFor(()->delayed.launches.get()==1,"late Intent not submitted");LayeredVpnService.TorCompareTrial ticket=LayeredVpnService.last;late.cancel();late.close();ticket.activate();check(done.await(3,TimeUnit.SECONDS)&&failure.get()!=null&&!ticket.up&&ticket.closed,"late service start revived cancelled owner");
  reset();Owner nativePending=new Owner();LayeredVpnService.failClose=true;AndroidTorCompareRuntime retained=create(nativePending);try{retained.run();throw new AssertionError("unproved close admitted another candidate");}catch(Exception expected){}check(retained.newCandidate("server","https://1.0.0.1/cdn-cgi/trace")==null&&RouterTorCompare.opened.size()==1,"partial native owner released before drain");Object pendingRound=retainedRound(retained);check(pendingRound!=null,"failed native cleanup discarded its retained round");try{retained.close();throw new AssertionError("failed native close was called drained");}catch(Exception expected){}check(retainedRound(retained)==pendingRound,"failed close discarded its exact retryable round");LayeredVpnService.failClose=false;retained.close();check(retainedRound(retained)==null,"completed retry retained cross-language round cycle");check(LayeredVpnService.last.closed&&LayeredVpnService.discards.get()==1,"retry lost exact partial owner");
  reset();Owner network=new Owner();LayeredVpnService.delayLaunch=true;AndroidTorCompareRuntime moving=create(network);done=new CountDownLatch(1);failure=run(moving,done);waitFor(()->network.launches.get()==1,"network candidate not started");AndroidMAXDNSOwner.network++;check(done.await(3,TimeUnit.SECONDS)&&failure.get()!=null,"physical network replacement did not cancel");moving.close();check(LayeredVpnService.last.closed,"network owner not drained");
  for(int i=0;i<32;i++){reset();Owner race=new Owner();RouterTorCompare.keeping=new CountDownLatch(1);RouterTorCompare.keepRelease=new CountDownLatch(1);AndroidTorCompareRuntime transferring=create(race);done=new CountDownLatch(1);failure=run(transferring,done);check(RouterTorCompare.keeping.await(3,TimeUnit.SECONDS),"final repeat not reached");transferring.cancel();RouterTorCompare.keepRelease.countDown();check(done.await(3,TimeUnit.SECONDS)&&failure.get()!=null,"cancelled transfer succeeded");transferring.close();check(LayeredVpnService.last.closed&&!LayeredVpnService.last.kept,"cancelled transfer retained native authority");}
  System.out.println("Android Tor comparison host: "+checks+" checks (native coordinator and engine boundaries doubled)");
 }
}
'''

def write(root,path,text):
    f=root/path;f.parent.mkdir(parents=True,exist_ok=True);f.write_text(text)

def compile_run(root,main):
    classes=root/'classes';subprocess.run(['javac','--release','17','-encoding','UTF-8','-d',str(classes),*[str(p) for p in root.rglob('*.java')]],check=True,timeout=45)
    return subprocess.run(['java','-cp',str(classes),main],check=True,timeout=45,text=True,capture_output=True).stdout

def host_gate():
    with tempfile.TemporaryDirectory(prefix='routervpn-tor-compare-host-') as d:
        root=Path(d);app='com/eabusham/routervpn/';box='io/nekohasekai/libbox/'
        write(root,app+'AndroidTorCompareRuntime.java',(JAVA/'AndroidTorCompareRuntime.java').read_text())
        write(root,app+'AndroidStandardExitController.java',(JAVA/'AndroidStandardExitController.java').read_text())
        write(root,app+'HostStubs.java',HOST_STUBS);write(root,app+'TorCompareHarness.java',HOST_HARNESS)
        write(root,'android/content/Context.java','package android.content;public class Context{public Context getApplicationContext(){return this;}}')
        write(root,box+'RouterTorCompareHost.java','package io.nekohasekai.libbox;public interface RouterTorCompareHost{boolean current();RouterTorCompareCandidate newCandidate(String execution,String target);void progress(String stage,String execution);}')
        write(root,box+'RouterTorCompareCandidate.java','package io.nekohasekai.libbox;public interface RouterTorCompareCandidate{boolean current();void start()throws Exception;CommandServer server();RouterTorProofRequest proof();void cancel();void close()throws Exception;}')
        for name in ('CommandServer','RouterTorProofRequest'):write(root,box+name+'.java','package io.nekohasekai.libbox;public final class '+name+'{}')
        write(root,box+'RouterTorCompare.java',GO_ROUND)
        write(root,box+'Libbox.java','package io.nekohasekai.libbox;public final class Libbox{public static RouterTorCompare routerTorNewCompare(RouterTorCompareHost host,String entry,String exit,String mode,String sha)throws Exception{if(RouterTorCompare.failFactory||!sha.matches("[0-9a-f]{64}"))throw new Exception("bad capture");RouterTorCompare.transport=mode;return new RouterTorCompare(host);}}')
        print(compile_run(root,'com.eabusham.routervpn.TorCompareHarness'),end='')

SERVICE_HARNESS=r'''package com.eabusham.routervpn;
import java.io.*;import java.lang.reflect.*;import java.util.concurrent.*;import java.util.concurrent.atomic.*;import io.nekohasekai.libbox.*;
public final class TorServiceHarness{
 static int checks;static void check(boolean x,String why){checks++;if(!x)throw new AssertionError(why);}
 static Field field(Class<?> c,String n)throws Exception{Field f=c.getDeclaredField(n);f.setAccessible(true);return f;}
 static Object get(Object o,String n)throws Exception{return field(o.getClass(),n).get(o);}
 static void set(Object o,String n,Object v)throws Exception{field(o.getClass(),n).set(o,v);}
 static Object call(Object o,String name,Class<?>[] types,Object...args)throws Exception{Method m=o.getClass().getDeclaredMethod(name,types);m.setAccessible(true);try{return m.invoke(o,args);}catch(InvocationTargetException e){Throwable cause=e.getCause();if(cause instanceof Exception)throw(Exception)cause;throw e;}}
 static long epoch(LayeredVpnService s)throws Exception{return((AtomicLong)get(s,"lifecycle")).get();}
 static final class Fixture implements AutoCloseable{
  final LayeredVpnService service=new LayeredVpnService();final android.net.Network network=new android.net.Network();final AndroidMAXDNSOwner.Physical physical=new AndroidMAXDNSOwner.Physical();final NativeSingBoxController.SessionInfo prepared=new NativeSingBoxController.SessionInfo("candidate-source","standard-tor");final LayeredVpnService.TorCompareTrial trial;final CommandServer server;final AndroidTorSession tor;final File folder;volatile boolean alive=true;
  Fixture()throws Exception{
   Libbox.closeFail=false;Libbox.closeEntered=null;Libbox.closeRelease=null;service.onCreate();physical.network=network;
   trial=LayeredVpnService.TorCompareTrial.reserve(prepared,"external-tor","local",physical,()->alive);trial.submit();
   check((boolean)call(trial,"bind",new Class[]{LayeredVpnService.class},service),"fresh candidate did not bind");
   server=new CommandServer(service,service);tor=new AndroidTorSession(new org.json.JSONObject("{}"),"config",server,null);tor.sessionID=prepared.sessionId;tor.externalID="external-tor";
   folder=new File(service.getFilesDir(),"layered-sessions/"+prepared.sessionId);folder.mkdirs();new File(folder,"owner").createNewFile();
   set(service,"commandServer",server);set(service,"torSession",tor);set(service,"torOwner",true);set(service,"torPhysicalNetwork",network);set(service,"activeSession",folder);set(service,"activeMode",prepared.modeId);set(service,"state","UP");
   call(trial,"finished",new Class[]{boolean.class,String.class},true,"");
   check(trial.current()&&trial.server()==server&&trial.proof()==tor.proof,"native receipt was substituted");
  }
  public void close()throws Exception{Libbox.closeFail=false;if(Libbox.closeRelease!=null)Libbox.closeRelease.countDown();if(!(boolean)get(trial,"kept"))trial.close();service.onDestroy();((ExecutorService)get(service,"executor")).awaitTermination(3,TimeUnit.SECONDS);}
 }
 static android.content.Intent marked(String id){android.content.Intent i=new android.content.Intent();i.action=LayeredVpnService.ACTION_START;i.values.put(LayeredVpnService.EXTRA_SESSION_ID,id);i.values.put(LayeredVpnService.EXTRA_MODE_ID,"standard-tor");i.values.put(LayeredVpnService.EXTRA_TOR_COMPARISON,id);return i;}
 public static void main(String[] args)throws Exception{
  Thread.setDefaultUncaughtExceptionHandler((thread,error)->{error.printStackTrace();System.exit(1);});
  try(Fixture f=new Fixture()){long before=epoch(f.service);f.trial.cancel();check(epoch(f.service)==before+1&&!f.trial.current()&&f.tor.cancelled,"cancel did not revoke exact proof/generation");check(!(boolean)get(f.service,"explicitStop"),"trial cancel changed global Stop");f.trial.close();check(get(f.service,"commandServer")==null&&get(f.service,"activeSession")==null&&!f.folder.exists(),"native or private owner was released early");check("DOWN".equals(get(f.service,"state"))&&f.service.stops==0,"ordinary trial stop destroyed the comparison service");}
  try(Fixture f=new Fixture()){Libbox.closeEntered=new CountDownLatch(1);Libbox.closeRelease=new CountDownLatch(1);CountDownLatch done=new CountDownLatch(1);AtomicReference<Throwable> failed=new AtomicReference<>();new Thread(()->{try{f.trial.close();}catch(Throwable e){failed.set(e);}finally{done.countDown();}}).start();check(Libbox.closeEntered.await(3,TimeUnit.SECONDS),"actual checked native close did not enter");check(!done.await(50,TimeUnit.MILLISECONDS)&&get(f.service,"commandServer")==f.server&&f.folder.exists(),"blocked native close falsely acknowledged");boolean rejected=false;try{LayeredVpnService.TorCompareTrial.reserve(new NativeSingBoxController.SessionInfo("replacement","standard-tor"),"external-tor","server",f.physical,()->true);}catch(IllegalStateException expected){rejected=true;}check(rejected,"new candidate borrowed draining owner");Libbox.closeRelease.countDown();check(done.await(3,TimeUnit.SECONDS)&&failed.get()==null,"native acknowledgment failed to release exact owner");}
  try(Fixture f=new Fixture()){Libbox.closeFail=true;boolean rejected=false;try{f.trial.close();}catch(IllegalStateException pending){rejected=true;}check(rejected&&get(f.service,"commandServer")==f.server&&f.folder.exists()&&!(boolean)get(f.trial,"closed"),"failed checked close dropped owner");Libbox.closeFail=false;f.trial.close();check((boolean)get(f.trial,"closed")&&!f.folder.exists(),"retry failed to drain captured owner");}
  try(Fixture f=new Fixture()){f.trial.keep();long before=epoch(f.service);f.trial.cancel();f.trial.close();check(epoch(f.service)==before&&get(f.service,"commandServer")==f.server&&f.trial.current()&&!f.tor.cancelled,"old comparison revoked transferred winner");check(get(f.service,"torCompareTrial")==null&&field(LayeredVpnService.class,"reservedTorCompare").get(null)==null,"kept owner retained trial registry");}
  try(Fixture f=new Fixture()){long before=epoch(f.service);android.content.Intent stale=marked("unknown-old-trial");f.service.onStartCommand(stale,0,9);check(epoch(f.service)==before&&get(f.service,"commandServer")==f.server&&f.service.stops==0,"late marked intent revoked replacement");f.service.onStartCommand(marked(f.prepared.sessionId),0,10);check(epoch(f.service)==before&&get(f.service,"commandServer")==f.server,"duplicate marked intent changed captured epoch");}
  try(Fixture f=new Fixture()){f.trial.close();long before=epoch(f.service);f.service.onStartCommand(marked(f.prepared.sessionId),0,11);check(epoch(f.service)==before&&get(f.service,"commandServer")==null&&f.service.lastStopID==11,"cancelled late start entered ordinary launch or missed foreground cleanup");}
  LayeredVpnService fresh=new LayeredVpnService();fresh.onCreate();AndroidMAXDNSOwner.Physical physical=new AndroidMAXDNSOwner.Physical();physical.network=new android.net.Network();LayeredVpnService.TorCompareTrial unseen=LayeredVpnService.TorCompareTrial.reserve(new NativeSingBoxController.SessionInfo("never-seen","standard-tor"),"external-tor","local",physical,()->true);unseen.submit();unseen.close();long before=epoch(fresh);fresh.onStartCommand(marked("never-seen"),0,12);check(epoch(fresh)==before&&get(fresh,"torCompareTrial")==null&&fresh.lastStopID==12,"revoked unseen launch was resurrected");fresh.onDestroy();
  try(Fixture f=new Fixture()){File replacement=new File(f.service.getFilesDir(),"replacement");replacement.mkdirs();set(f.service,"activeSession",replacement);boolean rejected=false;try{f.trial.close();}catch(IllegalStateException expected){rejected=true;}check(rejected&&get(f.service,"commandServer")==f.server&&replacement.exists(),"old candidate closed replacement session");set(f.service,"activeSession",f.folder);f.trial.close();}
  for(int i=0;i<64;i++)try(Fixture f=new Fixture()){CountDownLatch go=new CountDownLatch(1);AtomicBoolean kept=new AtomicBoolean();Thread a=new Thread(()->{try{go.await();f.trial.keep();kept.set(true);}catch(Exception rejected){}});Thread b=new Thread(()->{try{go.await();f.trial.cancel();}catch(Exception impossible){throw new AssertionError(impossible);}});a.start();b.start();go.countDown();a.join(3000);b.join(3000);check(!a.isAlive()&&!b.isAlive(),"transfer/cancel deadlocked");f.trial.close();if(kept.get())check(get(f.service,"commandServer")==f.server&&!f.tor.cancelled,"successful transfer was revoked by old cancellation");else check(get(f.service,"commandServer")==null,"cancelled transfer retained native data authority");}
  System.out.println("Actual LayeredVpnService Tor comparison: "+checks+" checks (Android/native APIs doubled)");
 }
}
'''

def service_gate():
    spec=importlib.util.spec_from_file_location('layered_types',ROOT/'android/test_android_layered_service_compile.py')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    stubs=dict(module.STUBS)
    context=stubs['android/content/Context.java']
    context=context.replace('public Object getSystemService(String name){return null;}','public Object getSystemService(String name){return name.equals(CONNECTIVITY_SERVICE)?new android.net.ConnectivityManager():new android.app.NotificationManager();}')
    context=context.replace('public java.io.File getFilesDir(){return null;}','public java.io.File getFilesDir(){return new java.io.File(System.getProperty("fixture.files"));}')
    context=context.replace('public SharedPreferences getSharedPreferences(String a,int b){return null;}','public SharedPreferences getSharedPreferences(String a,int b){return ()->new SharedPreferences.Editor(){public SharedPreferences.Editor putString(String k,String v){return this;}public void apply(){}};}')
    stubs['android/content/Context.java']=context
    stubs['android/content/Intent.java']='package android.content;public class Intent{public String action="";public final java.util.Map<String,String> values=new java.util.HashMap<>();public String getAction(){return action;}public String getStringExtra(String k){return values.get(k);}public long getLongExtra(String k,long d){return d;}}'
    stubs['android/app/Service.java']=stubs['android/app/Service.java'].replace('public void stopSelf(){} public void stopSelf(int id){}','public int stops,lastStopID;public void stopSelf(){stops++;} public void stopSelf(int id){stops++;lastStopID=id;}')
    tor=stubs['com/eabusham/routervpn/AndroidTorSession.java']
    tor=tor.replace('public final String sessionID="",externalID="";','public String sessionID="",externalID="";public volatile boolean cancelled;public final io.nekohasekai.libbox.RouterTorProofRequest proof=new io.nekohasekai.libbox.RouterTorProofRequest();')
    tor=tor.replace('public boolean comparisonCurrent(){return false;}','public boolean comparisonCurrent(){return !cancelled;}')
    tor=tor.replace('comparisonProof()throws Exception{return null;}','comparisonProof()throws Exception{return proof;}').replace('public void cancel(){}','public void cancel(){cancelled=true;}').replace('public boolean healthy(){return false;}','public boolean healthy(){return !cancelled;}')
    stubs['com/eabusham/routervpn/AndroidTorSession.java']=tor
    lib=stubs['io/nekohasekai/libbox/Libbox.java']
    lib=lib.replace('public static void routerStrategyCloseService(CommandServer server)throws Exception{}','public static volatile boolean closeFail;public static volatile java.util.concurrent.CountDownLatch closeEntered,closeRelease;public static void routerStrategyCloseService(CommandServer server)throws Exception{if(closeFail)throw new Exception("native close unconfirmed");if(closeEntered!=null){closeEntered.countDown();closeRelease.await();}}')
    stubs['io/nekohasekai/libbox/Libbox.java']=lib
    with tempfile.TemporaryDirectory(prefix='routervpn-tor-compare-service-') as d:
        root=Path(d)
        for path,text in stubs.items():write(root,path,text)
        write(root,'com/eabusham/routervpn/LayeredVpnService.java',(JAVA/'LayeredVpnService.java').read_text())
        write(root,'com/eabusham/routervpn/TorServiceHarness.java',SERVICE_HARNESS)
        classes=root/'classes';subprocess.run(['javac','--release','17','-encoding','UTF-8','-d',str(classes),*[str(p) for p in root.rglob('*.java')]],check=True,timeout=45)
        files=root/'files';files.mkdir()
        result=subprocess.run(['java','-Dfixture.files='+str(files),'-cp',str(classes),'com.eabusham.routervpn.TorServiceHarness'],check=True,timeout=45,text=True,capture_output=True)
        print(result.stdout,end='')

def mutation_gate():
    global JAVA
    original=JAVA
    cases=[
        ('kept cross-language owner','AndroidTorCompareRuntime.java','if(round==created)round=null;','/* mutation: retained transferred proxy */',host_gate,'successful transfer retained cross-language round cycle'),
        ('drained cross-language owner','AndroidTorCompareRuntime.java','if(round==captured)round=null;','/* mutation: retained drained proxy */',host_gate,'successful failure cleanup retained cross-language round cycle'),
        ('pending cross-language owner','AndroidTorCompareRuntime.java','}finally{stopWatch();}','}finally{stopWatch();synchronized(lock){if(round==captured)round=null;}}',host_gate,'failed close discarded its exact retryable round'),
        ('captured exit transport','AndroidTorCompareRuntime.java','exit.id,exit.protocol,captureSHA','exit.id,entryMode,captureSHA',host_gate,'candidate transport borrowed entry mode'),
        ('captured external endpoint','AndroidTorCompareRuntime.java','||capturedTarget!=null&&!capturedTarget.equals(target)','',host_gate,'comparison changed the selected external endpoint'),
        ('pending Start join','AndroidTorCompareRuntime.java','if(started)await(startDone,25_000_000_000L,"Tor candidate startup has not drained.");','',host_gate,'close falsely joined entered preparation'),
        ('changed source admission','AndroidTorCompareRuntime.java','owner.requireSource();','/* mutation: source witness omitted */',host_gate,'changed source admitted'),
        ('captured restoration leaf','AndroidStandardExitController.java','String leaf=restoredExecution.isEmpty()?execution:restoredExecution;','String leaf="local";',host_gate,'restoration reran Compare or changed winner'),
        ('late Intent revocation','LayeredVpnService.java','rejectTorComparisonStart(startId);return Service.START_NOT_STICKY;','lifecycle.incrementAndGet();rejectTorComparisonStart(startId);return Service.START_NOT_STICKY;',service_gate,'late marked intent revoked replacement'),
        ('native drain acknowledgment','LayeredVpnService.java','throw new IllegalStateException("Native captured-path teardown has not completed.");','/* mutation: native close failure discarded */',service_gate,'failed checked close dropped owner'),
        ('transferred owner cancellation','LayeredVpnService.java','synchronized(this){if(kept)return;cancelled=true;}','synchronized(this){cancelled=true;}',service_gate,'old comparison revoked transferred winner'),
    ]
    for label,name,before,after,run,expected in cases:
        with tempfile.TemporaryDirectory(prefix='routervpn-tor-compare-mutation-') as d:
            candidate=Path(d)
            for source in ('AndroidTorCompareRuntime.java','AndroidStandardExitController.java','LayeredVpnService.java'):
                shutil.copyfile(original/source,candidate/source)
            target=candidate/name;text=target.read_text();assert before in text,(label,'missing mutation anchor')
            target.write_text(text.replace(before,after))
            JAVA=candidate
            try:
                with contextlib.redirect_stdout(io.StringIO()):run()
            except subprocess.CalledProcessError as error:
                assert expected in (error.stderr or ''),(label,'did not reach intended runtime assertion',error.stderr)
            else:raise AssertionError(label+' escaped executable ownership coverage')
            finally:JAVA=original
    print('Android Tor comparison: '+str(len(cases))+' executable negative controls rejected')

if __name__=='__main__':
    try:
        host_gate()
        service_gate()
        mutation_gate()
    except subprocess.CalledProcessError as error:
        if error.stdout: print(error.stdout,end='')
        if error.stderr: print(error.stderr,end='',file=sys.stderr)
        raise
