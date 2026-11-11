#!/usr/bin/env python3
"""Run shipping Speed Lab + unified bridge through captured restore/cancel transactions."""
from pathlib import Path
import importlib.util
import os
import re
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
JAVA = ROOT / 'android/app/src/main/java/com/eabusham/routervpn'
spec = importlib.util.spec_from_file_location('restore_startup_boundaries', ROOT/'android/test_android_startup_policy.py')
S = importlib.util.module_from_spec(spec)
spec.loader.exec_module(S)
P = S.P

OWNERS = r'''
final class AndroidHomeStateStore {
 static final class Snapshot {boolean connected;long pathGeneration;String sessionId="",phase="off",pathProof="not-run",logicalMode="",runtimeMode="",actualBase="",expectedExternalIp="",fallback="",activeNodeId="",activeEntryId="",activeExitId="",activeEntryMode="",activeExternalId="",activeExternalProtocol="",activeChain="";}
 static volatile Snapshot current=new Snapshot();static int serial;static boolean emergency;
 static Snapshot snapshot(Context c){return current;}
 static boolean emergencyDisconnectPending(Context c){return emergency;}
 static Snapshot copy(){Snapshot a=current,b=new Snapshot();b.connected=a.connected;b.pathGeneration=a.pathGeneration;b.sessionId=a.sessionId;b.phase=a.phase;b.pathProof=a.pathProof;b.logicalMode=a.logicalMode;b.runtimeMode=a.runtimeMode;b.actualBase=a.actualBase;b.expectedExternalIp=a.expectedExternalIp;b.fallback=a.fallback;b.activeNodeId=a.activeNodeId;b.activeEntryId=a.activeEntryId;b.activeExitId=a.activeExitId;b.activeEntryMode=a.activeEntryMode;b.activeExternalId=a.activeExternalId;b.activeExternalProtocol=a.activeExternalProtocol;b.activeChain=a.activeChain;return b;}
 static long advancePathGeneration(Context c){Snapshot s=copy();s.pathGeneration++;current=s;return s.pathGeneration;}
 static Snapshot begin(String topology,String raw,String entry,String exit,String mode,String external){Snapshot s=new Snapshot();s.pathGeneration=current.pathGeneration+1;s.sessionId="native-"+(++serial);s.logicalMode=topology;s.phase="connecting";s.pathProof="pending";s.runtimeMode=raw;s.activeNodeId=exit;s.activeEntryId=entry;s.activeExitId=exit;s.activeEntryMode=mode;s.activeExternalId=external;s.activeExternalProtocol=topology.equals("external")?raw:"";current=s;return s;}
 static void proved(){Snapshot s=copy();s.connected=true;s.phase="connected";s.pathProof="passed";current=s;RuntimeBoundary.proofs++;}
 static void off(){Snapshot s=new Snapshot();s.pathGeneration=current.pathGeneration+1;current=s;}
}
final class RuntimeBoundary {
 static volatile boolean holdConnect,holdRestore,holdStop,stopEntered,stopping;
 static volatile Runnable pendingConnect,pendingRestore,afterRestoredProof,afterOrdinaryProof,afterImportedProof;static volatile java.util.concurrent.CountDownLatch stopRelease;
 static int starts,stops,restores,proofs;static String restoredPins="",restoredRaw="",restoredLogical="",restoredExecution="",restoredEntry="",restoredExternal="";
 static void reset(){holdConnect=false;holdRestore=false;holdStop=false;stopEntered=false;stopping=false;pendingConnect=null;pendingRestore=null;afterRestoredProof=null;afterOrdinaryProof=null;afterImportedProof=null;stopRelease=new java.util.concurrent.CountDownLatch(1);starts=stops=restores=proofs=0;restoredRaw=restoredLogical=restoredExecution=restoredEntry=restoredExternal="";}
 static void ready(Runnable r){if(holdConnect)pendingConnect=r;else r.run();}
 static boolean stop(String id)throws Exception{if(!id.equals(AndroidHomeStateStore.current.sessionId))return false;stops++;stopping=true;AndroidHomeStateStore.Snapshot s=AndroidHomeStateStore.copy();if(s.connected)s.pathGeneration++;s.connected=false;s.phase="connecting";s.pathProof="pending";AndroidHomeStateStore.current=s;stopEntered=true;if(holdStop)stopRelease.await();boolean owned=id.equals(AndroidHomeStateStore.current.sessionId);if(owned)AndroidHomeStateStore.off();stopping=false;return owned;}
}
// Only native proof/drain completion is controlled. The full shipping Unified
// and Speed Lab owners consume the exact original all-member receipt.
final class AndroidNodeChainRuntime {
 interface Callback{void progress(String s);void finished(boolean ok,String s);default void owned(String s){}}
 Runnable beforeCapturedDrain;Context context;AndroidNodeStore.ChainCapture source,restoredSource;AndroidHomeStateStore.Snapshot home;boolean active;
 final Set<String> drained=new HashSet<>();
 static volatile boolean holdCapture;static java.util.concurrent.CountDownLatch captureEntered=new java.util.concurrent.CountDownLatch(1),captureRelease=new java.util.concurrent.CountDownLatch(1);
 static void workerOnly(){if(Thread.currentThread().getName().equals("main"))throw new AssertionError("ordered native/source verification ran on UI thread");}
 static final class RestoreCapture{final AndroidNodeStore.ChainCapture source;final AndroidHomeStateStore.Snapshot home;final String selection;RestoreCapture(AndroidNodeStore.ChainCapture source,AndroidHomeStateStore.Snapshot home)throws Exception{this.source=source;this.home=home;selection=AndroidConnectionSelection.digest(new Context(),new AndroidNodeStore(new Context()));}}
 static String chain(AndroidNodeStore.ChainCapture source)throws Exception{JSONArray values=new JSONArray();for(int i=0;i<source.members.size();i++)values.put(new JSONObject().put("id",source.members.get(i).id).put("mode",source.modes.get(i)));return values.toString();}
 void begin(AndroidNodeStore.ChainCapture captured)throws Exception{source=captured;AndroidHomeStateStore.begin("node-chain","node-chain","","","","");AndroidHomeStateStore.current.activeNodeId=captured.control.id;AndroidHomeStateStore.current.activeChain=chain(captured);home=AndroidHomeStateStore.copy();active=true;}
 boolean isActiveOrTransitioning(){return active;}boolean isConnected(){return active&&home!=null&&home.sessionId.equals(AndroidHomeStateStore.current.sessionId)&&AndroidHomeStateStore.current.connected;}
 List<AndroidNodeStore.ChainSource> activeSources(){return isConnected()?source.members:List.of();}List<String> activeModes(){return isConnected()?source.modes:List.of();}
 RestoreCapture captureRestore()throws Exception{workerOnly();if(holdCapture){captureEntered.countDown();if(!captureRelease.await(4,java.util.concurrent.TimeUnit.SECONDS))throw new AssertionError("ordered capture release missing");}source.requireCurrent();if(!isConnected())throw new IllegalStateException("original ordered owner missing");return new RestoreCapture(source,AndroidHomeStateStore.copy());}
 boolean captureCurrent(RestoreCapture capture){workerOnly();try{capture.source.requireCurrent();return isConnected()&&source==capture.source&&capture.home.sessionId.equals(AndroidHomeStateStore.current.sessionId)&&capture.home.pathGeneration==AndroidHomeStateStore.current.pathGeneration&&capture.home.activeChain.equals(AndroidHomeStateStore.current.activeChain);}catch(Exception changed){return false;}}
 boolean restoredMatches(RestoreCapture capture){workerOnly();try{capture.source.requireCurrent();return isConnected()&&source==capture.source&&chain(source).equals(AndroidHomeStateStore.current.activeChain)&&source.control.id.equals(AndroidHomeStateStore.current.activeNodeId);}catch(Exception changed){return false;}}
 void connect(AndroidNodeStore.ChainCapture captured,Callback callback){connect(captured,AndroidHomeStateStore.copy(),callback);}
 void connect(AndroidNodeStore.ChainCapture captured,AndroidHomeStateStore.Snapshot idle,String selection,Callback callback){try{AndroidConnectionSelection.requireCurrent(context,new AndroidNodeStore(context),selection);connect(captured,idle,callback);}catch(Exception changed){callback.finished(false,changed.toString());}}
 void connectLast(AndroidNodeStore.ChainCapture captured,AndroidHomeStateStore.Snapshot idle,String selection,Callback callback){throw new AssertionError("temporary restore must replay its original native capture, not Startup Last");}
 void connectLast(AndroidNodeStore.ChainCapture captured,AndroidHomeStateStore.Snapshot idle,Callback callback){throw new AssertionError("temporary restore must replay its original native capture, not Startup Last");}
 void connect(AndroidNodeStore.ChainCapture captured,AndroidHomeStateStore.Snapshot idle,Callback callback){try{captured.requireCurrent();if(active||idle==null||idle.connected||idle.pathGeneration!=AndroidHomeStateStore.current.pathGeneration||!idle.sessionId.equals(AndroidHomeStateStore.current.sessionId))throw new IllegalStateException("ordered launch lost original idle epoch");begin(captured);RuntimeBoundary.starts++;callback.owned(home.sessionId);RuntimeBoundary.ready(()->{AndroidHomeStateStore.proved();callback.finished(true,"controlled ordered proof");});}catch(Exception changed){callback.finished(false,changed.toString());}}
 boolean retainsCapturedOwner(String session){return active&&home!=null&&home.sessionId.equals(session);}
 boolean disconnectAndDrainCaptured(String session)throws Exception{workerOnly();if(beforeCapturedDrain!=null){Runnable fault=beforeCapturedDrain;beforeCapturedDrain=null;fault.run();}if(!active||home==null||!home.sessionId.equals(session))return false;boolean clean=RuntimeBoundary.stop(session);if(clean){drained.add(session);active=false;}return clean;}
 boolean stopAndProve(){try{return !active||disconnectAndDrainCaptured(home.sessionId);}catch(Exception failed){return false;}}
 void restore(RestoreCapture captured,AndroidHomeStateStore.Snapshot idle,Callback callback){workerOnly();try{if(captured==null||!drained.contains(captured.home.sessionId))throw new IllegalStateException("original ordered owner never drained");captured.source.requireCurrent();if(active||idle==null||idle.connected||idle.pathGeneration!=AndroidHomeStateStore.current.pathGeneration||!idle.sessionId.equals(AndroidHomeStateStore.current.sessionId))throw new IllegalStateException("ordered restore lost original idle epoch");begin(captured.source);restoredSource=captured.source;RuntimeBoundary.restores++;callback.owned(home.sessionId);Runnable finish=()->{AndroidHomeStateStore.proved();if(RuntimeBoundary.afterRestoredProof!=null)RuntimeBoundary.afterRestoredProof.run();callback.finished(true,"fresh ordered proof");};if(RuntimeBoundary.holdRestore)RuntimeBoundary.pendingRestore=finish;else finish.run();}catch(Exception changed){callback.finished(false,changed.toString());}}
}
final class AndroidModeOrchestrator {
 interface Callback{void progress(String message);void finished(boolean ok,String mode,String message);default void owned(String id){}default void proved(String session,String raw,String source){}}
 void startup(File f,String mode,String raw,String source,Callback cb){throw new AssertionError("temporary Speed Lab cannot become startup");}
 String source="";
 String captureSource(File f,String id,String raw)throws Exception{String now=Files.readString(f.toPath());if(!source.equals(now)||!id.equals(AndroidHomeStateStore.current.sessionId))throw new IllegalStateException("active exact source changed");return now;}
 void restoreCaptured(File f,String raw,String logical,String fallback,String expected,Callback cb){try{if(!expected.equals(Files.readString(f.toPath())))throw new IllegalStateException("changed original");RuntimeBoundary.restores++;RuntimeBoundary.restoredRaw=raw;RuntimeBoundary.restoredLogical=logical;source=expected;AndroidHomeStateStore.begin(logical,raw,"",node(f),"","");cb.owned(AndroidHomeStateStore.current.sessionId);Runnable finish=()->{AndroidHomeStateStore.proved();if(RuntimeBoundary.afterRestoredProof!=null)RuntimeBoundary.afterRestoredProof.run();cb.finished(true,raw,"fresh restored proof");};if(RuntimeBoundary.holdRestore)RuntimeBoundary.pendingRestore=finish;else finish.run();}catch(Exception e){cb.finished(false,"",e.toString());}}
 void disconnectCaptured(String id,Callback cb){new Thread(()->{try{cb.finished(RuntimeBoundary.stop(id),"","captured router drain");}catch(Exception e){cb.finished(false,"",e.toString());}}).start();}
 void disconnect(Callback cb){AndroidHomeStateStore.off();cb.finished(true,"","stopped");}
 static String node(File f){return f.getName().replace(".json","");}
 void start(File f,String logical,String raw,Callback cb){RuntimeBoundary.starts++;try{source=Files.readString(f.toPath());}catch(Exception e){cb.finished(false,"",e.toString());return;}AndroidHomeStateStore.begin(logical,raw,"",node(f),"","");cb.owned(AndroidHomeStateStore.current.sessionId);RuntimeBoundary.ready(()->{AndroidHomeStateStore.proved();cb.finished(true,raw,"proved test");});}
 void auto(File f,boolean smart,Callback cb){start(f,smart?"SMART AUTO":"AUTO","wg-pq",cb);}void all(File f,Callback cb){start(f,"ALL","max-quic-awg",cb);}void custom(File f,List<String> layers,Callback cb){start(f,"CUSTOM","reality-vision",cb);}void logical(File f,String mode,Callback cb){start(f,mode,mode,cb);}
}
final class AndroidMultihopRuntime {
 // MULTIHOP_CAPTURE_TYPES
 interface Callback{void progress(String s);void finished(boolean ok,String s);default void owned(String id){}}
 String execution="local",selected="local",serverPins="original-public-pins";
 // Native traffic is controlled here; the shipping imported compiler and source
 // capture are exercised separately by test_android_imported_router.py.
 AndroidStandardExitStore.Entry ordinaryEntry;
 AndroidStandardExitStore.Entry capturedOrdinaryEntry(AndroidHomeStateStore.Snapshot home){if(ordinaryEntry==null)return null;if(!home.connected||!home.sessionId.equals(AndroidHomeStateStore.current.sessionId)||!home.activeEntryId.equals(ordinaryEntry.id))throw new IllegalStateException("imported runtime owner changed");return AndroidStandardExitStore.copy(ordinaryEntry);}
 void connectImported(AndroidStandardExitStore.Entry entry,AndroidNodeStore.Node exit,String mode,String execution,Callback cb){try{AndroidImportedRouterPath.compile(entry,AndroidImportedRouterPath.finalBundle(exit.file),mode,execution);}catch(Exception error){cb.finished(false,error.toString());return;}ordinaryEntry=AndroidStandardExitStore.copy(entry);this.execution=selected=execution;RuntimeBoundary.starts++;AndroidHomeStateStore.begin("multihop",mode,entry.id,exit.id,AndroidExternalPolicy.protocol(entry.protocol),"");cb.owned(AndroidHomeStateStore.current.sessionId);RuntimeBoundary.ready(()->{AndroidHomeStateStore.proved();if(RuntimeBoundary.afterImportedProof!=null)RuntimeBoundary.afterImportedProof.run();cb.finished(true,"proved imported graph");});}
 RestoreCapture captureRestore(AndroidNodeStore.Node a,AndroidNodeStore.Node b,AndroidHomeStateStore.Snapshot home)throws Exception{return new RestoreCapture(execution,selected,home,a,b,serverPins);}
 boolean captureCurrent(RestoreCapture capture){return capture!=null&&capture.owner.matchesHome(AndroidHomeStateStore.current)&&capture.owner.pins.equals(serverPins)&&capture.policy.equals(execution)&&capture.selected.equals(selected)&&sameImported(capture.ordinary);}
 boolean sameImported(AndroidStandardExitStore.Entry expected){try{return expected==null?ordinaryEntry==null:ordinaryEntry!=null&&AndroidStandardExitStore.snapshot(expected).equals(AndroidStandardExitStore.snapshot(ordinaryEntry));}catch(Exception e){return false;}}
 boolean restoredMatches(RestoreCapture capture,AndroidNodeStore.Node a,AndroidNodeStore.Node b,AndroidHomeStateStore.Snapshot home){try{capture.require(a,b);return sameImported(capture.ordinary)&&capture.policy.equals(execution)&&capture.selected.equals(selected)&&capture.owner.pins.equals(serverPins)&&capture.owner.entryMode.equals(home.activeEntryMode)&&capture.owner.exitMode.equals(home.runtimeMode);}catch(Exception changed){return false;}}
 boolean isConnected(){return AndroidHomeStateStore.current.connected&&AndroidHomeStateStore.current.logicalMode.equals("multihop");}boolean isActiveOrTransitioning(){return isConnected();}
 String activeEntryId(){return AndroidHomeStateStore.current.activeEntryId;}String activeExitId(){return AndroidHomeStateStore.current.activeExitId;}String activeEntryMode(){return AndroidHomeStateStore.current.activeEntryMode;}String activeExitMode(){return AndroidHomeStateStore.current.runtimeMode;}String activeExecution(){return execution;}String activeSelectedExecution(){return selected;}
 boolean disconnectAndDrainCaptured(String id)throws Exception{return RuntimeBoundary.stop(id);}void disconnect(){}
 void connect(AndroidNodeStore.Node a,AndroidNodeStore.Node b,String mode,String exec,String entry,Callback cb){ordinaryEntry=null;RuntimeBoundary.starts++;execution=exec;selected=exec.equals("auto")?"server":exec;AndroidHomeStateStore.begin("multihop",mode,a.id,b.id,entry,"");cb.owned(AndroidHomeStateStore.current.sessionId);RuntimeBoundary.ready(()->{AndroidHomeStateStore.proved();cb.finished(true,"proved graph");});}
 void connectLast(AndroidNodeStore.Node a,AndroidNodeStore.Node b,StartupCapture capture,AndroidHomeStateStore.Snapshot idle,Callback cb){throw new AssertionError("temporary restore must use runtime-only capture");}
 void restoreCaptured(AndroidNodeStore.Node a,AndroidNodeStore.Node b,RestoreCapture capture,AndroidHomeStateStore.Snapshot idle,Callback cb){try{capture.require(a,b);}catch(Exception changed){cb.finished(false,changed.toString());return;}ordinaryEntry=capture.ordinary==null?null:AndroidStandardExitStore.copy(capture.ordinary);String mode=capture.owner.exitMode,policy=capture.policy,winner=capture.selected,entry=capture.owner.entryMode;RuntimeBoundary.restoredPins=capture.owner.pins;RuntimeBoundary.restores++;RuntimeBoundary.restoredExecution=winner;execution=policy;selected=winner;AndroidHomeStateStore.begin("multihop",mode,capture.owner.entryId,b.id,entry,"");cb.owned(AndroidHomeStateStore.current.sessionId);Runnable finish=()->{AndroidHomeStateStore.proved();if(RuntimeBoundary.afterRestoredProof!=null)RuntimeBoundary.afterRestoredProof.run();cb.finished(true,"fresh exact winner proof");};if(RuntimeBoundary.holdRestore)RuntimeBoundary.pendingRestore=finish;else finish.run();}
 List<NativeSingBoxController.ModeInfo> listSupportedExitModes(File f){return Collections.emptyList();}
}
final class AndroidStandardExitRuntime {
 // EXTERNAL_CAPTURE_TYPES
 final Context context=new Context();MeasurementSource activeMeasurementSource;
 boolean disconnectRequested,revalidationTeardown,teardownInProgress;
 final java.util.concurrent.atomic.AtomicBoolean closed=new java.util.concurrent.atomic.AtomicBoolean();
 String requestedExecution="local",torNativeSession="",externalNativeSession="";
 String execution="local",selected="local",restoredResponseMap="";
 AndroidStandardExitStore.Entry ordinaryEntry;
 // Explicit native adoption boundary. The source receipt and its current checks
 // above are shipping code; this fixture does not claim a real Android tunnel.
 void adopted(File router,AndroidStandardExitStore.Entry ordinary,AndroidStandardExitStore.Entry exit)throws Exception{
  String kind=router!=null?"router-vpn":ordinary!=null?"external":"direct";
  String source=router!=null?AndroidTorProfile.digest(AndroidPrivateFileStore.read(router,AndroidNodeStore.MAX_BUNDLE)):ordinary!=null?AndroidStandardExitStore.snapshot(ordinary):"";
  requestedExecution=execution;torNativeSession=externalNativeSession=AndroidHomeStateStore.current.sessionId;
  activeMeasurementSource=new MeasurementSource(AndroidHomeStateStore.copy(),externalNativeSession,AndroidStandardExitStore.snapshot(exit),kind,source,router==null?null:router.getCanonicalFile(),execution,selected);
 }
 AndroidStandardExitStore.Entry capturedOrdinaryEntry(AndroidHomeStateStore.Snapshot s){if(ordinaryEntry==null)return null;if(!s.connected||!s.sessionId.equals(AndroidHomeStateStore.current.sessionId)||!s.activeEntryId.equals(ordinaryEntry.id))throw new IllegalStateException("ordinary runtime owner changed");return AndroidStandardExitStore.copy(ordinaryEntry);}
 String capturedRequestedExecution(AndroidHomeStateStore.Snapshot s){return execution;}String capturedExternalExecution(AndroidHomeStateStore.Snapshot s){return selected;}
 void connect(File f,AndroidStandardExitStore.Entry e,String mode,String execution,Callback cb){this.execution=execution;selected=execution.equals("auto")?"server":execution;connect(f,e,mode,cb);}
 void restoreCaptured(File f,AndroidStandardExitStore.Entry e,String mode,String execution,String winner,Callback cb){RuntimeBoundary.restores++;RuntimeBoundary.restoredExecution=winner;this.execution=execution;selected=winner;restoredResponseMap=e.responseMap;connect(f,e,mode,new Callback(){public void owned(String id){cb.owned(id);}public void progress(String message){cb.progress(message);}public void finished(boolean ok,String message){if(ok&&RuntimeBoundary.afterRestoredProof!=null)RuntimeBoundary.afterRestoredProof.run();cb.finished(ok,message);}});}
 interface Callback{void progress(String s);void finished(boolean ok,String s);default void owned(String id){}}
 boolean isActiveOrTransitioning(){return AndroidHomeStateStore.current.connected&&AndroidHomeStateStore.current.logicalMode.equals("external");}
 String capturedTorExit(AndroidHomeStateStore.Snapshot s){return "8.8.4.4";}String capturedExternalExit(AndroidHomeStateStore.Snapshot s){return "8.8.4.4";}
 void disconnect(){}boolean disconnectCaptured(String id)throws Exception{return RuntimeBoundary.stop(id);}boolean disconnectAndDrainCaptured(String id)throws Exception{return RuntimeBoundary.stop(id);}
 void connectDirect(AndroidStandardExitStore.Entry e,Callback cb){connect(null,e,"",cb);}void connect(File f,AndroidStandardExitStore.Entry e,String mode,Callback cb){ordinaryEntry=null;RuntimeBoundary.starts++;AndroidHomeStateStore.begin("external",e.protocol,f==null?"":AndroidModeOrchestrator.node(f),"",mode,e.id);cb.owned(AndroidHomeStateStore.current.sessionId);RuntimeBoundary.ready(()->{try{AndroidHomeStateStore.proved();adopted(f,null,e);cb.finished(true,"proved external");}catch(Exception failure){cb.finished(false,failure.toString());}});}
 void connectOrdinary(AndroidStandardExitStore.Entry entry,AndroidStandardExitStore.Entry exit,String execution,Callback cb){ordinaryEntry=AndroidStandardExitStore.copy(entry);this.execution=execution;selected=execution;RuntimeBoundary.starts++;AndroidHomeStateStore.begin("external",exit.protocol,entry.id,"",AndroidExternalPolicy.protocol(entry.protocol),exit.id);cb.owned(AndroidHomeStateStore.current.sessionId);RuntimeBoundary.ready(()->{try{AndroidHomeStateStore.proved();adopted(null,ordinaryEntry,exit);if(RuntimeBoundary.afterOrdinaryProof!=null)RuntimeBoundary.afterOrdinaryProof.run();cb.finished(true,"proved ordinary Tor");}catch(Exception failure){cb.finished(false,failure.toString());}});}
}
'''
capture_types=P.MULTIHOP_CAPTURE_TYPES.replace('final CapturedSource entrySource,exitSource;', 'final CapturedSource entrySource,exitSource;final AndroidStandardExitStore.Entry ordinary;')
capture_types=capture_types.replace('entrySource=new CapturedSource(entry.file);', 'ordinary=entry==null?AndroidStandardExitStore.copy(AndroidRuntimeRegistry.instance.multihop.ordinaryEntry):null;entrySource=entry==null?null:new CapturedSource(entry.file);')
capture_types=capture_types.replace('if(!owner.entryId.equals(entry.id)||!owner.exitId.equals(exit.id))', 'if(!(entry==null?ordinary!=null&&owner.entryId.equals(ordinary.id):ordinary==null&&owner.entryId.equals(entry.id))||!owner.exitId.equals(exit.id))')
capture_types=capture_types.replace('entrySource.require(entry.file);', 'if(ordinary!=null){if(!AndroidStandardExitStore.snapshot(ordinary).equals(AndroidStandardExitStore.snapshot(AndroidStandardExitStore.saved.get(ordinary.id))))throw new IllegalStateException("changed captured imported source");}else entrySource.require(entry.file);')
OWNERS = OWNERS.replace('// MULTIHOP_CAPTURE_TYPES',capture_types)
external_runtime=(JAVA/'AndroidStandardExitRuntime.java').read_text()
EXTERNAL_CAPTURE_TYPES='\n'.join(S.block(external_runtime, signature) for signature in (
    'static final class MeasurementSource {',
    'synchronized MeasurementSource captureMeasurementSource(',
    'synchronized void requireMeasurementSource('))
OWNERS = OWNERS.replace('// EXTERNAL_CAPTURE_TYPES',EXTERNAL_CAPTURE_TYPES)

METERS = r'''
// Saved preference/private-store boundary; the real profile store has its own
// executable transactional tests. The actual dialog consumes this exact tuple.
final class AndroidConnectionProfileStore {
 static ExternalSelection saved;
 static final class ExternalSelection {final AndroidNodeStore.Node entry;final AndroidStandardExitStore.Entry ordinaryEntry,exit;final String entryMode,execution;ExternalSelection(AndroidNodeStore.Node e,AndroidStandardExitStore.Entry x,String m,String c){this(e,null,x,m,c);}ExternalSelection(AndroidNodeStore.Node e,AndroidStandardExitStore.Entry ordinary,AndroidStandardExitStore.Entry x,String m,String c){entry=e;ordinaryEntry=ordinary;exit=x;entryMode=m;execution=c;}boolean direct(){return entry==null&&ordinaryEntry==null;}}
 AndroidConnectionProfileStore(Context c,AndroidNodeStore n,AndroidStandardExitStore e){}
 ExternalSelection currentExternalPath(String id){if(saved==null||!saved.exit.id.equals(id))throw new IllegalStateException("stale saved selection");return saved;}
}
final class LayeredVpnService {static final class HopMeasurementOwner{private HopMeasurementOwner(){throw new AssertionError("ordinary restoration fixture has no external benchmark owner");}}static java.util.function.Consumer<Throwable> quiesce;static int automatic;static void quiesceMTUForSpeedLab(java.util.function.Consumer<Throwable> cb){quiesce=cb;}static void startAutomaticMTU(){automatic++;}}
final class AndroidSpeedLab {
 interface Callback{void finished(Result result,Throwable error);}static final class Latency{double medianMs,p90Ms;String detail(){return "latency";}}static final class Transfer{double mbps,bufferbloatMs;Latency loadedLatency=new Latency();}static final class Result{Latency idle=new Latency();Transfer download=new Transfer(),upload=new Transfer();String pathIdentity="captured";org.json.JSONObject json(){return new org.json.JSONObject();}String summary(){return "measured";}}
 // PRODUCTION_DURATION
 static double round(double n){return n;}static volatile Callback pending;static int starts,cancels;static boolean active;
 AndroidSpeedLab(android.app.Activity a){}void run(String m,double l,double h,Callback cb){starts++;active=true;pending=cb;}void cancel(){cancels++;}
 static void drained(boolean cancel){active=false;Callback cb=pending;pending=null;cb.finished(cancel?null:new Result(),cancel?new java.util.concurrent.CancellationException("http drained"):null);}
}
final class AndroidNativeHopMeasurement {
 interface Callback{void progress(String status);void finished(String status,Throwable error);}static boolean hold;static volatile Callback pending;static int starts,cancels;
 void run(Object lease,Callback cb){if(!AndroidMTUMeasurementGate.owns(lease))throw new AssertionError("native probe lost outer MTU lease");starts++;pending=cb;if(!hold)drained(false);}void cancel(){cancels++;}
 static void drained(boolean cancel){Callback cb=pending;pending=null;cb.finished(cancel?null:"native results drained",cancel?new java.util.concurrent.CancellationException("native drained"):null);}
}
final class AndroidHopMeasurementDialog{AndroidHopMeasurementDialog(android.app.Activity a,AndroidUnifiedConnectionController c){}void show(){}static String renderStatus(String s){return s;}}
final class AndroidSpeedLabHopMeter{static final class Hop{String summary(){return "hop";}}}
// Ordinary Speed Lab tests cannot mint a completed external 50-sample result.
// The comparison fixture supplies its explicitly controlled native boundary.
final class AndroidExternalNodeStatistics {static final class Record {private Record(){throw new AssertionError("no external native result in ordinary Speed Lab fixture");}}}
final class AndroidExternalNodeBenchmark {
 interface OwnedCallback {void progress(String status);void finished(AndroidExternalNodeStatistics.Record result,AndroidStandardExitRuntime.MeasurementSource source,Throwable error);}
 AndroidExternalNodeBenchmark(Context c,AndroidStandardExitRuntime runtime){}
 void run(String id,Object lease,OwnedCallback callback){throw new AssertionError("ordinary Speed Lab cannot request external native50");}
 void cancel(){throw new AssertionError("ordinary Speed Lab cannot own external native50");}
}
'''
HARNESS = r'''package com.eabusham.routervpn;
import android.app.*;import java.nio.file.*;import java.util.*;import org.json.*;
public final class SpeedLabRestoreTest {
 static int checks;static void check(boolean v,String msg){checks++;if(!v)throw new AssertionError(msg);}
 interface Condition{boolean ready();}static void waitFor(Condition c,String msg)throws Exception{long until=System.nanoTime()+3_000_000_000L;while(!c.ready()&&System.nanoTime()<until)Thread.sleep(2);check(c.ready(),msg);}
 static final class Result implements AndroidSpeedLabController.Callback {volatile int count;volatile Throwable error;volatile AndroidSpeedLab.Result result;public void progress(String s){}public void finished(AndroidSpeedLab.Result r,Throwable e){result=r;error=e;count++;}}
 static final class Fixture {
  final Activity activity=new Activity();final AndroidNodeStore nodes=new AndroidNodeStore(activity);final AndroidUnifiedConnectionController connection;final AndroidSpeedLabController controller;final Result result=new Result();final AndroidSpeedLabController.Request request=new AndroidSpeedLabController.Request();
  final AndroidNodeStore.Node original,first,last;final AndroidStandardExitStore.Entry external=new AndroidStandardExitStore.Entry();AndroidStandardExitStore.Entry originalOrdinary;final String type;String raw;boolean originalImported;String originalSession,originalWinner="server";boolean originalDirect;
  Fixture(Path directory,String type,String topology)throws Exception{check(!AndroidMTUMeasurementGate.held(),"previous case leaked hold");this.type=type;this.raw=type.equals("multihop")?"max-quic-awg":type.startsWith("external")?type.substring(9):"reality-pq-vision";
   RuntimeBoundary.reset();android.content.Context.speedPreferences.clear();AndroidConnectionProfileStore.saved=null;AndroidHomeStateStore.current=new AndroidHomeStateStore.Snapshot();AndroidHomeStateStore.emergency=false;AndroidRuntimeRegistry.instance=new AndroidRuntimeRegistry();AndroidVpnMutationGuard.busy=false;AndroidNodeStore.nodes.clear();AndroidStandardExitStore.saved.clear();android.net.VpnService.needsPermission=false;AndroidSpeedLab.starts=AndroidSpeedLab.cancels=0;AndroidSpeedLab.pending=null;AndroidNativeHopMeasurement.starts=AndroidNativeHopMeasurement.cancels=0;AndroidNativeHopMeasurement.hold=false;AndroidNativeHopMeasurement.pending=null;LayeredVpnService.quiesce=null;LayeredVpnService.automatic=0;
   original=node(directory,"original");first=node(directory,"entry");last=node(directory,"exit");external.protocol=type.startsWith("external")?raw:"tor-bridge";if(type.equals("external-openvpn"))external.responseMap="captured-private-two-host-map";AndroidStandardExitStore.saved.put(external.id,AndroidStandardExitStore.copy(external));
   connection=new AndroidUnifiedConnectionController(activity,nodes);controller=new AndroidSpeedLabController(activity,connection);
   if(type.equals("router")){AndroidHomeStateStore.begin("SMART AUTO",raw,"",original.id,"","");AndroidRuntimeRegistry.instance.orchestrator.source=Files.readString(original.file.toPath());AndroidHomeStateStore.proved();}
   if(type.equals("multihop")){AndroidHomeStateStore.begin("multihop",raw,original.id,last.id,"reality-xhttp","");AndroidRuntimeRegistry.instance.multihop.execution="auto";AndroidRuntimeRegistry.instance.multihop.selected="server";AndroidHomeStateStore.proved();}
   if(type.startsWith("external")){AndroidHomeStateStore.begin("external",raw,original.id,"","max-quic-awg",external.id);AndroidHomeStateStore.proved();captureOriginal();}
   originalSession=AndroidHomeStateStore.current.sessionId;
   request.scope="temporary";request.topology=topology;request.node=first;request.entry=first;request.exit=last;request.mode="all";request.entryMode="wg-pq";request.exitMode="shadowsocks";request.execution="external".equals(topology)?"local":"server";request.standardExit=external;request.externalDirect=false;
  }
  AndroidNodeStore.Node node(Path root,String id)throws Exception{Path folder=Files.createTempDirectory(root,id);Path file=folder.resolve(id+".json");Files.writeString(file,"{\"private\":\""+id+"\",\"dns\":\"home-adguard\",\"mtu\":\"auto\"}");AndroidNodeStore.Node n=new AndroidNodeStore.Node(id,file.toFile());AndroidNodeStore.nodes.add(n);return n;}
  void start(){controller.run(request,result);}void quiesce(){try{waitFor(()->LayeredVpnService.quiesce!=null||result.count>0,"original capture never completed");}catch(Exception error){throw new IllegalStateException(error);}check(LayeredVpnService.quiesce!=null,"transaction rejected its valid original before MTU drain: "+result.error);LayeredVpnService.quiesce.accept(null);}void measured()throws Exception{waitFor(()->AndroidSpeedLab.pending!=null,"measurement never started");AndroidSpeedLab.drained(false);}
  void complete()throws Exception{waitFor(()->result.count>0,"transaction never completed");check(result.count==1&&!controller.isRunning()&&!AndroidMTUMeasurementGate.held(),"completion did not release its drained lease exactly once");}
  AndroidStandardExitStore.Entry ordinary(String protocol,String id){AndroidStandardExitStore.Entry value=new AndroidStandardExitStore.Entry();value.id=id;value.name="Ordinary "+protocol;value.protocol=protocol;value.secret="ordinary-private-"+id;value.policy="ordinary-policy-"+id;AndroidStandardExitStore.saved.put(id,AndroidStandardExitStore.copy(value));return value;}
  void captureOriginal()throws Exception{AndroidStandardExitRuntime runtime=AndroidRuntimeRegistry.instance.standardExit;runtime.adopted(originalOrdinary!=null||AndroidHomeStateStore.current.activeEntryId.isEmpty()?null:original.file,originalOrdinary,external);}
  void ordinaryOriginal(String protocol)throws Exception{originalOrdinary=ordinary(protocol,original.id);AndroidStandardExitRuntime runtime=AndroidRuntimeRegistry.instance.standardExit;runtime.ordinaryEntry=AndroidStandardExitStore.copy(originalOrdinary);runtime.execution=runtime.selected="local";AndroidHomeStateStore.begin("external",external.protocol,original.id,"",AndroidExternalPolicy.protocol(protocol),external.id);AndroidHomeStateStore.proved();captureOriginal();originalSession=AndroidHomeStateStore.current.sessionId;}
  void directOriginal()throws Exception{originalDirect=true;AndroidStandardExitRuntime runtime=AndroidRuntimeRegistry.instance.standardExit;runtime.ordinaryEntry=null;runtime.execution=runtime.selected="local";AndroidHomeStateStore.begin("external",external.protocol,"","","",external.id);AndroidHomeStateStore.proved();captureOriginal();originalSession=AndroidHomeStateStore.current.sessionId;}
  void ordinaryTemporary(String protocol){request.ordinaryEntry=ordinary(protocol,first.id);request.entry=null;request.entryMode=AndroidExternalPolicy.protocol(protocol);request.execution="local";request.externalDirect=false;request.topology="external";}
  void pairedFinal()throws Exception{Files.writeString(last.file.toPath(),new JSONObject().put("private","original-final-credential").put("dns","home-adguard-encrypted").put("start_layer","original-final-aes-xor").put("mtu","fixed-1280").put("profiles",new JSONObject()).put("modes",new JSONArray()).put("availableFinals",new JSONArray(List.of("shadowsocks","reality-vision"))).toString());}
  void importedTemporary(String protocol)throws Exception{ordinaryTemporary(protocol);request.topology="multihop";request.standardExit=null;request.exitMode="reality-vision";pairedFinal();}
  void importedOriginal(String protocol)throws Exception{originalImported=true;originalOrdinary=ordinary(protocol,original.id);pairedFinal();raw="reality-vision";AndroidMultihopRuntime runtime=AndroidRuntimeRegistry.instance.multihop;runtime.ordinaryEntry=AndroidStandardExitStore.copy(originalOrdinary);runtime.execution=runtime.selected="local";AndroidHomeStateStore.begin("multihop",raw,originalOrdinary.id,last.id,AndroidExternalPolicy.protocol(protocol),"");AndroidHomeStateStore.proved();originalSession=AndroidHomeStateStore.current.sessionId;}
  void originalRestored()throws Exception{AndroidHomeStateStore.Snapshot s=AndroidHomeStateStore.current;check(s.connected&&s.pathProof.equals("passed")&&!s.sessionId.equals(originalSession),"original lacks fresh proof/session");check(s.runtimeMode.equals(raw),"original raw transport changed");if(originalImported){AndroidStandardExitStore.Entry actual=AndroidRuntimeRegistry.instance.multihop.capturedOrdinaryEntry(s);check(actual!=null&&AndroidStandardExitStore.snapshot(actual).equals(AndroidStandardExitStore.snapshot(originalOrdinary))&&s.activeEntryId.equals(originalOrdinary.id)&&s.activeExitId.equals(last.id)&&s.activeEntryMode.equals(AndroidExternalPolicy.protocol(originalOrdinary.protocol))&&AndroidRuntimeRegistry.instance.multihop.execution.equals("local")&&AndroidRuntimeRegistry.instance.multihop.selected.equals("local")&&RuntimeBoundary.restoredExecution.equals("local"),"imported original credentials/policy/graph/execution changed");}else if(type.equals("router"))check(s.logicalMode.equals("SMART AUTO")&&s.activeNodeId.equals(original.id)&&RuntimeBoundary.restoredRaw.equals(raw),"SMART AUTO was reselected or node changed");if(type.equals("multihop"))check(s.activeEntryId.equals(original.id)&&s.activeEntryMode.equals("reality-xhttp")&&s.activeExitId.equals(last.id)&&AndroidRuntimeRegistry.instance.multihop.execution.equals("auto")&&AndroidRuntimeRegistry.instance.multihop.selected.equals(originalWinner)&&RuntimeBoundary.restoredExecution.equals(originalWinner),"original multihop execution/entry changed");if(type.startsWith("external")){if(originalDirect)check(s.activeExternalId.equals(external.id)&&s.activeEntryId.isEmpty()&&s.activeEntryMode.isEmpty(),"direct external restoration acquired another entry");else if(originalOrdinary==null)check(s.activeExternalId.equals(external.id)&&s.activeEntryMode.equals("max-quic-awg")&&s.activeEntryId.equals(original.id),"external original entry or profile changed");else{AndroidStandardExitStore.Entry actual=AndroidRuntimeRegistry.instance.standardExit.capturedOrdinaryEntry(s);check(actual!=null&&AndroidStandardExitStore.snapshot(actual).equals(AndroidStandardExitStore.snapshot(originalOrdinary))&&s.activeEntryMode.equals(AndroidExternalPolicy.protocol(originalOrdinary.protocol))&&s.activeExternalId.equals(external.id),"ordinary original source/kind/path changed");}}check(nodes.activeId().equals("original"),"temporary path rewrote selected saved node");}
 }
 static void matrix(Path root)throws Exception{
  for(String original:new String[]{"router","multihop","external-openvpn","external-amneziawg","external-tor","external-tor-bridge"})for(String topology:new String[]{"router","multihop","external","system-direct"}){
   Fixture f=new Fixture(root,original,topology);String before=Files.readString(f.original.file.toPath());f.start();check(AndroidHomeStateStore.current.connected&&AndroidSpeedLab.starts==0,"original was stopped before MTU drain");f.quiesce();f.measured();f.complete();check(f.result.error==null&&f.result.result!=null,"valid temporary test failed: "+original+"/"+topology+" "+f.result.error);f.originalRestored();check(Files.readString(f.original.file.toPath()).equals(before),"restoration changed stored policy");check(RuntimeBoundary.stops==(topology.equals("system-direct")?1:2),"wrong graph cleanup count");check(AndroidNativeHopMeasurement.starts==((topology.equals("external")||topology.equals("multihop"))?1:0),"multihop or external bypassed owned native measurement");
  }
 }
 static void exactMultihopWinner(Path root)throws Exception{
  for(String selected:new String[]{"local","server"})for(String topology:new String[]{"router","multihop","external","system-direct"}){
   Fixture f=new Fixture(root,"multihop",topology);f.originalWinner=selected;AndroidRuntimeRegistry.instance.multihop.selected=selected;f.start();f.quiesce();f.measured();f.complete();
   check(f.result.error==null,"exact prior winner restore failed");f.originalRestored();check(RuntimeBoundary.proofs>=(topology.equals("system-direct")?2:3),"winner restore reused an old proof");
  }
 }
 static void exactExternalWinner(Path root)throws Exception{
  for(String kind:new String[]{"external-shadowsocks","external-openvpn","external-tor","external-tor-bridge"})for(String selected:new String[]{"local","server"})for(String topology:new String[]{"router","multihop","external","system-direct"}){
   Fixture f=new Fixture(root,kind,topology);AndroidStandardExitRuntime owner=AndroidRuntimeRegistry.instance.standardExit;owner.execution="auto";owner.selected=selected;f.captureOriginal();
   f.start();f.quiesce();f.measured();f.complete();check(f.result.error==null,"external winner restoration failed");f.originalRestored();
   check(owner.execution.equals("auto")&&owner.selected.equals(selected)&&RuntimeBoundary.restoredExecution.equals(selected)&&owner.restoredResponseMap.equals(f.external.responseMap),"external Compare was rerun instead of restoring its proved winner");
  }
 }
 static void exactTorExecution(Path root)throws Exception{
  for(String kind:new String[]{"external-tor","external-tor-bridge"})for(String selected:new String[]{"local","server"})for(String topology:new String[]{"router","multihop","external","system-direct"}){
   Fixture f=new Fixture(root,kind,topology);AndroidStandardExitRuntime owner=AndroidRuntimeRegistry.instance.standardExit;owner.execution=selected;owner.selected=selected;f.captureOriginal();
   if(topology.equals("external"))f.request.execution=selected;
   f.start();f.quiesce();f.measured();f.complete();check(f.result.error==null,"captured Tor execution restoration failed");f.originalRestored();
   check(owner.execution.equals(selected)&&owner.selected.equals(selected),"Tor Server was replaced by Local during restore");
   if(selected.equals("server"))check(RuntimeBoundary.restoredExecution.equals("server"),"Tor Server did not use captured restoration");
  }
  Fixture replaced=new Fixture(root,"external-tor-bridge","router");AndroidStandardExitRuntime owner=AndroidRuntimeRegistry.instance.standardExit;owner.execution="server";owner.selected="server";replaced.captureOriginal();
  RuntimeBoundary.afterRestoredProof=()->owner.selected="local";replaced.start();replaced.quiesce();replaced.measured();replaced.complete();
  check(replaced.result.error!=null&&replaced.result.result==null,"Tor retained a score after restoration switched execution");
 }
 static void changeOriginalSource(Fixture f,String change)throws Exception{
  AndroidStandardExitRuntime runtime=AndroidRuntimeRegistry.instance.standardExit;
  AndroidStandardExitStore.Entry saved=AndroidStandardExitStore.saved.get(f.external.id);
  switch(change){
   case "exit-key":saved.secret="same-ID replacement private credential";break;
   case "exit-policy":saved.policy="same-ID replacement DNS and MTU";break;
   case "exit-expected":saved.expectedPublicIp="1.1.1.1";break;
   case "exit-response":saved.responseMap="replacement private response map";break;
   case "exit-removed":AndroidStandardExitStore.saved.remove(f.external.id);break;
   case "entry-file":Files.writeString(f.original.file.toPath(),"{\"private\":\"same-ID replacement Router key\"}");break;
   case "entry-relocated":{Path file=Files.createTempDirectory(f.original.file.toPath().getParent(),"relinked").resolve(f.original.file.getName());Files.copy(f.original.file.toPath(),file);AndroidNodeStore.nodes.removeIf(n->n.id.equals(f.original.id));AndroidNodeStore.nodes.add(new AndroidNodeStore.Node(f.original.id,file.toFile()));break;}
   case "entry-removed":if(f.originalOrdinary==null)AndroidNodeStore.nodes.removeIf(n->n.id.equals(f.original.id));else AndroidStandardExitStore.saved.remove(f.originalOrdinary.id);break;
   case "ordinary-key":AndroidStandardExitStore.saved.get(f.originalOrdinary.id).secret="same-ID replacement ordinary credential";break;
   case "ordinary-policy":AndroidStandardExitStore.saved.get(f.originalOrdinary.id).policy="same-ID replacement ordinary DNS";break;
   case "ordinary-protocol":AndroidStandardExitStore.saved.get(f.originalOrdinary.id).protocol="https";break;
   case "ordinary-native":runtime.ordinaryEntry.secret="replacement native entry snapshot";break;
   case "native-session":runtime.externalNativeSession=runtime.torNativeSession="replacement-native-owner";break;
   case "native-requested":runtime.requestedExecution="auto";break;
   case "native-selected":runtime.selected="server";break;
   case "native-missing":runtime.activeMeasurementSource=null;break;
   case "native-replaced":f.captureOriginal();break;
   case "native-disconnect":runtime.disconnectRequested=true;break;
   case "native-closed":runtime.closed.set(true);break;
   case "native-revalidation":runtime.revalidationTeardown=true;break;
   case "native-teardown":runtime.teardownInProgress=true;break;
   case "emergency":AndroidHomeStateStore.emergency=true;break;
   default:{AndroidHomeStateStore.Snapshot home=AndroidHomeStateStore.copy();switch(change){
    case "home-generation":home.pathGeneration++;break;
    case "home-base":home.actualBase="replacement-base";break;
    case "home-expected":home.expectedExternalIp="1.0.0.1";break;
    case "home-proof":home.pathProof="failed";break;
    default:throw new AssertionError("unknown source mutation "+change);
   }AndroidHomeStateStore.current=home;}
  }
 }
 static void externalOriginalSources(Path root)throws Exception{
  for(String kind:List.of("direct","router","ordinary"))for(String stage:List.of("capture","drain")){
   List<String> changes=new ArrayList<>(List.of("exit-key","exit-policy","exit-expected","exit-response","exit-removed","native-session","native-requested","native-selected","native-missing","native-disconnect","native-closed","native-revalidation","native-teardown","home-generation","home-base","home-expected","home-proof","emergency"));
   if(kind.equals("router"))changes.addAll(List.of("entry-file","entry-relocated","entry-removed"));
   if(kind.equals("ordinary"))changes.addAll(List.of("ordinary-key","ordinary-policy","ordinary-protocol","ordinary-native","entry-removed"));
   if(stage.equals("drain"))changes.add("native-replaced");
   for(String change:changes){
    Fixture f=new Fixture(root,kind.equals("ordinary")?"external-tor-bridge":"external-openvpn","router");
    if(kind.equals("ordinary"))f.ordinaryOriginal("socks5");else if(kind.equals("direct"))f.directOriginal();
    if(stage.equals("drain")){f.start();check(f.result.count==0&&AndroidMTUMeasurementGate.held(),"original source capture failed before the drift boundary");}
    changeOriginalSource(f,change);
    String label=kind+"/"+stage+"/"+change;
    if(stage.equals("capture"))f.start();else f.quiesce();
    try{f.complete();}catch(AssertionError failure){throw new AssertionError("original source rejection did not complete: "+label+", starts="+RuntimeBoundary.starts+", stops="+RuntimeBoundary.stops,failure);}
    check(f.result.error!=null&&f.result.result==null,"changed original external source was accepted: "+label);
    check(RuntimeBoundary.stops==0&&RuntimeBoundary.starts==0&&RuntimeBoundary.restores==0,"source drift stopped or replaced the original connection: "+label);
    check(AndroidSpeedLab.starts==0&&AndroidNativeHopMeasurement.starts==0,"source drift reached a measurement: "+label);
    check(AndroidHomeStateStore.current.connected&&AndroidHomeStateStore.current.sessionId.equals(f.originalSession),"source drift tore down the original owner: "+label);
   }
  }
  // A direct path has no Router source. Mutation of the colliding saved Router
  // record must not invent that dependency, and restoration still needs new proof.
  for(String topology:List.of("router","multihop","external","system-direct")){
   Fixture direct=new Fixture(root,"external-openvpn",topology);direct.directOriginal();
   direct.start();Files.writeString(direct.original.file.toPath(),"unrelated same-ID Router change");direct.quiesce();direct.measured();direct.complete();
   check(direct.result.error==null,"direct external inherited an unrelated Router source");direct.originalRestored();
  }
 }
 static void ordinaryRestoration(Path root)throws Exception{
  for(String protocol:List.of("wireguard","amneziawg","socks5","http","https","shadowsocks","hysteria2","openvpn"))for(String topology:List.of("router","multihop","external","ordinary","system-direct")){
   Fixture f=new Fixture(root,"external-tor-bridge",topology.equals("ordinary")?"external":topology);f.ordinaryOriginal(protocol);if(topology.equals("ordinary"))f.ordinaryTemporary(protocol);
   String first=Files.readString(f.original.file.toPath()),source=AndroidStandardExitStore.snapshot(f.originalOrdinary);f.start();check(AndroidHomeStateStore.current.sessionId.equals(f.originalSession)&&AndroidSpeedLab.starts==0,"ordinary original stopped before MTU drain");f.quiesce();f.measured();f.complete();
   check(f.result.error==null&&f.result.result!=null,"ordinary restoration failed: "+protocol+"/"+topology+" "+f.result.error);f.originalRestored();check(source.equals(AndroidStandardExitStore.snapshot(AndroidStandardExitStore.saved.get(f.original.id)))&&first.equals(Files.readString(f.original.file.toPath())),"ordinary restoration rewrote credentials or colliding private Router source");check(AndroidRuntimeRegistry.instance.standardExit.execution.equals("local")&&AndroidRuntimeRegistry.instance.standardExit.selected.equals("local"),"ordinary restore selected Server/Compare");
  }
  Fixture collision=new Fixture(root,"external-tor-bridge","router");collision.ordinaryOriginal("socks5");collision.start();Files.writeString(collision.original.file.toPath(),"unrelated Router credential changed");collision.quiesce();collision.measured();collision.complete();check(collision.result.error==null,"ordinary restoration captured an unrelated Router file with the same ID");collision.originalRestored();
 }
 static void ordinaryRestoreChanges(Path root)throws Exception{
  for(String stage:List.of("cleanup","permission"))for(String source:List.of("entry-key","entry-policy","entry-removed","exit-key","exit-policy","exit-removed")){
   Fixture f=new Fixture(root,"external-tor-bridge","router");f.ordinaryOriginal("https");f.start();f.quiesce();waitFor(()->AndroidSpeedLab.pending!=null,"ordinary original test did not measure");
   if(stage.equals("cleanup")){RuntimeBoundary.holdStop=true;RuntimeBoundary.stopEntered=false;}else android.net.VpnService.needsPermission=true;AndroidSpeedLab.drained(false);
   if(stage.equals("cleanup"))waitFor(()->RuntimeBoundary.stopEntered,"temporary cleanup was not captured");else{waitFor(()->f.result.count>0,"revoked original permission did not finish restoration refusal");check(f.activity.permissionRequest==0&&!f.connection.isPermissionPending(),"automatic restoration opened a new permission prompt");}
   String id=source.startsWith("entry")?f.originalOrdinary.id:f.external.id;if(source.endsWith("removed"))AndroidStandardExitStore.saved.remove(id);else if(source.endsWith("policy"))AndroidStandardExitStore.saved.get(id).policy="changed during original restore";else AndroidStandardExitStore.saved.get(id).secret="replacement original private source";
   if(stage.equals("cleanup")){RuntimeBoundary.holdStop=false;RuntimeBoundary.stopRelease.countDown();}else{android.net.VpnService.needsPermission=false;f.connection.onActivityResult(f.activity.permissionRequest,Activity.RESULT_OK);}f.complete();
   check(f.result.error!=null&&f.result.result==null&&RuntimeBoundary.starts==1&&!AndroidHomeStateStore.current.connected,"changed ordinary original was restored or kept a successful result: "+stage+"/"+source);
  }
  for(String change:List.of("key","policy","kind","execution")){
   Fixture f=new Fixture(root,"external-tor-bridge","router");f.ordinaryOriginal("socks5");AndroidStandardExitRuntime runtime=AndroidRuntimeRegistry.instance.standardExit;
   RuntimeBoundary.afterOrdinaryProof=()->{if(change.equals("kind"))runtime.ordinaryEntry=null;else if(change.equals("key"))runtime.ordinaryEntry.secret="substituted proved entry";else if(change.equals("policy"))runtime.ordinaryEntry.policy="substituted proved DNS";else runtime.selected="server";};
   f.start();f.quiesce();f.measured();f.complete();check(f.result.error!=null&&f.result.result==null,"substituted ordinary restored runtime kept a score: "+change);
  }
  Fixture temporary=new Fixture(root,"router","external");temporary.ordinaryTemporary("socks5");RuntimeBoundary.afterOrdinaryProof=()->AndroidRuntimeRegistry.instance.standardExit.ordinaryEntry.secret="substituted temporary native source";temporary.start();temporary.quiesce();temporary.complete();check(temporary.result.error!=null&&temporary.result.result==null&&AndroidSpeedLab.starts==0,"substituted temporary ordinary proof reached the meter");temporary.originalRestored();
 }
 static void cancellation(Path root)throws Exception{
  for(String stage:new String[]{"quiesce","suspend","permission","connect","http","hop","cleanup","restore"}){
   Fixture f=new Fixture(root,"router",stage.equals("hop")?"multihop":"external");
   if(stage.equals("suspend"))RuntimeBoundary.holdStop=true;
   if(stage.equals("permission"))android.net.VpnService.needsPermission=true;
   if(stage.equals("connect"))RuntimeBoundary.holdConnect=true;
   if(stage.equals("hop"))AndroidNativeHopMeasurement.hold=true;
   if(stage.equals("restore"))RuntimeBoundary.holdRestore=true;
   f.start();if(stage.equals("quiesce")){f.controller.cancel();check(f.result.count==0&&AndroidMTUMeasurementGate.held(),"cancel abandoned MTU quiescence");f.quiesce();f.complete();check(AndroidHomeStateStore.current.sessionId.equals(f.originalSession),"quiescence cancel replaced untouched original");continue;}
   f.quiesce();
   if(stage.equals("suspend")){waitFor(()->RuntimeBoundary.stopEntered,"original stop missing");f.controller.cancel();check(f.result.count==0&&AndroidMTUMeasurementGate.held(),"cancel released blocked stop");RuntimeBoundary.holdStop=false;RuntimeBoundary.stopRelease.countDown();}
   else if(stage.equals("permission")){waitFor(()->f.activity.permissionRequest!=0,"permission not requested");f.controller.cancel();android.net.VpnService.needsPermission=false;}
   else if(stage.equals("connect")){waitFor(()->RuntimeBoundary.pendingConnect!=null,"connection not captured");f.controller.cancel();}
   else{
    waitFor(()->AndroidSpeedLab.pending!=null,"HTTP did not start");
    if(stage.equals("http")){f.controller.cancel();check(AndroidSpeedLab.cancels==1&&f.result.count==0&&AndroidMTUMeasurementGate.held()&&RuntimeBoundary.stops==1,"cancel did not retain HTTP and temporary path until drain");AndroidSpeedLab.drained(true);}
    else{if(stage.equals("cleanup")){RuntimeBoundary.holdStop=true;RuntimeBoundary.stopEntered=false;}AndroidSpeedLab.drained(false);
     if(stage.equals("hop")){waitFor(()->AndroidNativeHopMeasurement.pending!=null,"native hop did not start");f.controller.cancel();check(AndroidNativeHopMeasurement.cancels==1&&RuntimeBoundary.stops==1&&f.result.count==0&&AndroidMTUMeasurementGate.held(),"native-hop cancel skipped actual drain");AndroidNativeHopMeasurement.drained(true);}
     if(stage.equals("cleanup")){waitFor(()->RuntimeBoundary.stopEntered,"test cleanup missing");f.controller.cancel();check(f.result.count==0&&AndroidMTUMeasurementGate.held(),"cancel abandoned temporary cleanup");RuntimeBoundary.holdStop=false;RuntimeBoundary.stopRelease.countDown();}
     if(stage.equals("restore")){waitFor(()->RuntimeBoundary.pendingRestore!=null,"restoration never started");f.controller.cancel();check(f.result.count==0&&AndroidMTUMeasurementGate.held(),"cancel abandoned original proof");RuntimeBoundary.pendingRestore.run();}
    }
   }
   f.complete();check(f.result.error!=null&&f.result.result==null,"cancel kept a successful score");if(!stage.equals("permission"))f.originalRestored();
  }
 }
 static void stale(Path root)throws Exception{
  for(String mutation:new String[]{"node","multihop-node","external-profile","external-map","newer-connected","manual-off","during-stop","restored-proof"}){
   Fixture f=new Fixture(root,(mutation.equals("node")||mutation.equals("external-profile")||mutation.equals("external-map"))?"external-openvpn":mutation.equals("multihop-node")?"multihop":"router","external");f.start();f.quiesce();waitFor(()->AndroidSpeedLab.pending!=null,"stale fixture not measured");
   if(mutation.equals("node")||mutation.equals("multihop-node"))Files.writeString(f.original.file.toPath(),"changed original DNS");
   if(mutation.equals("external-profile")){AndroidStandardExitStore.Entry e=AndroidStandardExitStore.copy(f.external);e.secret="replacement key";AndroidStandardExitStore.saved.put(e.id,e);}
   if(mutation.equals("external-map")){AndroidStandardExitStore.Entry e=AndroidStandardExitStore.copy(f.external);e.responseMap="replacement-owner-map";AndroidStandardExitStore.saved.put(e.id,e);}
   if(mutation.equals("newer-connected")){AndroidHomeStateStore.begin("new-user","wg","","new-node","","");AndroidHomeStateStore.proved();}
   if(mutation.equals("manual-off"))AndroidHomeStateStore.off();
   if(mutation.equals("during-stop")){RuntimeBoundary.holdStop=true;RuntimeBoundary.stopEntered=false;}
   if(mutation.equals("restored-proof"))RuntimeBoundary.afterRestoredProof=()->{AndroidHomeStateStore.begin("new-user","wg","","new-node","","");AndroidHomeStateStore.proved();};
   AndroidSpeedLab.drained(false);
   if(mutation.equals("during-stop")){waitFor(()->RuntimeBoundary.stopEntered,"cleanup not started");AndroidHomeStateStore.advancePathGeneration(f.activity);RuntimeBoundary.holdStop=false;RuntimeBoundary.stopRelease.countDown();}
   f.complete();check(f.result.error!=null&&f.result.result==null,"stale transaction kept result");check(RuntimeBoundary.restores==(mutation.equals("restored-proof")?1:0),"stale transaction restored old runtime");if(mutation.equals("newer-connected")||mutation.equals("restored-proof"))check(AndroidHomeStateStore.current.logicalMode.equals("new-user")&&AndroidHomeStateStore.current.connected,"cleanup disconnected replacement");
  }
 }


 static void multihopPins(Path root)throws Exception{
  for(String phase:new String[]{"before-stop","after-restore"}){
   Fixture f=new Fixture(root,"multihop","external");f.start();
   if(phase.equals("before-stop"))AndroidRuntimeRegistry.instance.multihop.serverPins="replacement-public-pins";
   f.quiesce();
   if(phase.equals("after-restore")){
    waitFor(()->AndroidSpeedLab.pending!=null,"pin fixture did not measure temporary path");
    RuntimeBoundary.afterRestoredProof=()->AndroidRuntimeRegistry.instance.multihop.serverPins="replacement-public-pins";
    AndroidSpeedLab.drained(false);
   }
   f.complete();check(f.result.error!=null&&f.result.result==null,"changed Server identities retained a temporary result: "+phase);
   if(phase.equals("before-stop"))check(RuntimeBoundary.stops==0&&RuntimeBoundary.restores==0&&AndroidHomeStateStore.current.sessionId.equals(f.originalSession),"changed original Server owner was stopped or restored");
   else check(RuntimeBoundary.restores==1&&RuntimeBoundary.restoredPins.equals("original-public-pins"),"restoration did not forward original public identities");
  }
 }

 static void permissionCapture(Path root)throws Exception{
  for(String topology:new String[]{"router","multihop","external"}){
   Fixture f=new Fixture(root,"router",topology);android.net.VpnService.needsPermission=true;f.start();f.quiesce();waitFor(()->f.activity.permissionRequest!=0,"permission boundary never reached");
   Files.writeString(f.first.file.toPath(),"changed test credentials during permission");android.net.VpnService.needsPermission=false;f.connection.onActivityResult(f.activity.permissionRequest,Activity.RESULT_OK);f.complete();
   check(f.result.error!=null&&RuntimeBoundary.starts==0&&AndroidSpeedLab.starts==0,"permission completion used changed test profile: "+topology);f.originalRestored();
  }
 }
 static void permissionSelection(Path root)throws Exception{
  for(String topology:List.of("router","multihop","external","ordinary"))for(boolean changed:new boolean[]{false,true}){
   Fixture f=new Fixture(root,"router",topology.equals("ordinary")?"external":topology);if(topology.equals("ordinary"))f.ordinaryTemporary("socks5");
   android.content.Context.speedPreferences.put("selected_kind","router-vpn");android.content.Context.speedPreferences.put("selected_id",f.original.id);android.content.Context.speedPreferences.put("mode","custom:Saved original");android.content.Context.speedPreferences.put("custom_presets","SAVED_LAYERS_DIFFERENT_FROM_TEST");
   Map<String,String> saved=new HashMap<>(android.content.Context.speedPreferences);android.net.VpnService.needsPermission=true;f.start();f.quiesce();waitFor(()->f.activity.permissionRequest!=0,"temporary permission boundary never reached");
   check(f.connection.isPermissionPending()&&f.connection.isActiveOrTransitioning()&&RuntimeBoundary.starts==0,"temporary permission owner was invisible to Product busy/cancel");
   if(changed)android.content.Context.speedPreferences.put("mode","user replacement choice");else android.content.Context.speedPreferences.put("map_theme","dark");
   android.net.VpnService.needsPermission=false;f.connection.onActivityResult(f.activity.permissionRequest,Activity.RESULT_OK);
   if(!changed)f.measured();f.complete();f.originalRestored();
   if(changed)check(f.result.error!=null&&f.result.result==null&&RuntimeBoundary.starts==0&&AndroidSpeedLab.starts==0&&android.content.Context.speedPreferences.get("mode").equals("user replacement choice"),"changed saved choice launched temporary test or overwrote user choice");
   else{check(f.result.error==null&&f.result.result!=null&&RuntimeBoundary.starts==1,"temporary path was required to equal saved selection");android.content.Context.speedPreferences.remove("map_theme");check(saved.equals(android.content.Context.speedPreferences),"permission-approved temporary path rewrote saved selection");}
  }
 }
 static void uiCancellation(Path root)throws Exception{
  for(boolean dismiss:new boolean[]{false,true}){
   Fixture f=new Fixture(root,"router","external");AndroidSpeedLabDialog ui=new AndroidSpeedLabDialog(f.activity,f.nodes,f.connection,f.controller);ui.show();
   java.lang.reflect.Field runField=AndroidSpeedLabDialog.class.getDeclaredField("run"),cancelField=AndroidSpeedLabDialog.class.getDeclaredField("cancel");runField.setAccessible(true);cancelField.setAccessible(true);
   android.widget.Button run=(android.widget.Button)runField.get(ui),cancel=(android.widget.Button)cancelField.get(ui);
   check(!cancel.isEnabled()&&run.performClick(),"Speed Lab initial buttons unavailable");check(cancel.isEnabled()&&!run.isEnabled()&&AndroidMTUMeasurementGate.held(),"run did not expose owned Cancel");
   LayeredVpnService.quiesce.accept(null);waitFor(()->AndroidSpeedLab.pending!=null,"UI measurement never started");
   if(dismiss)android.app.AlertDialog.last.dismiss();else check(cancel.performClick(),"Cancel button callback missing");
   check(AndroidSpeedLab.cancels==1&&f.controller.isRunning()&&AndroidMTUMeasurementGate.held(),"UI cancel or dismissal abandoned actual HTTP drain");
   AndroidSpeedLab.drained(true);waitFor(()->!f.controller.isRunning(),"UI cancellation never finalized");check(!AndroidMTUMeasurementGate.held()&&run.isEnabled()&&!cancel.isEnabled(),"UI completion failed to restore action buttons");check(AndroidHomeStateStore.current.sessionId.equals(f.originalSession),"current-path cancel replaced the existing connection");
  }
 }

 static android.widget.Spinner spinner(AndroidSpeedLabDialog dialog,String name)throws Exception{java.lang.reflect.Field field=AndroidSpeedLabDialog.class.getDeclaredField(name);field.setAccessible(true);return (android.widget.Spinner)field.get(dialog);}
 static android.widget.Button runButton(AndroidSpeedLabDialog dialog)throws Exception{java.lang.reflect.Field field=AndroidSpeedLabDialog.class.getDeclaredField("run");field.setAccessible(true);return (android.widget.Button)field.get(dialog);}
 static void externalUI(Path root)throws Exception{
  for(String protocol:new String[]{"shadowsocks","tor","tor-bridge"})for(String requested:new String[]{"local","server","auto"}){
   Fixture f=new Fixture(root,"router","external");f.external.protocol=protocol;AndroidStandardExitStore.saved.put(f.external.id,AndroidStandardExitStore.copy(f.external));
   JSONObject profiles=new JSONObject();JSONArray modes=new JSONArray();for(String mode:new String[]{"wg","max-quic-awg","reality-xhttp"}){profiles.put(mode,new JSONObject());modes.put(new JSONObject().put("id",mode).put("name",mode));}Files.writeString(f.first.file.toPath(),new JSONObject().put("profiles",profiles).put("modes",modes).toString());
   AndroidConnectionProfileStore.saved=new AndroidConnectionProfileStore.ExternalSelection(f.first,AndroidStandardExitStore.copy(f.external),"reality-xhttp","auto");
   android.content.Context.speedPreferences.put("selected_kind","external");android.content.Context.speedPreferences.put("selected_id",f.external.id);
   Map<String,String> saved=new HashMap<>(android.content.Context.speedPreferences);
   AndroidSpeedLabDialog ui=new AndroidSpeedLabDialog(f.activity,f.nodes,f.connection,f.controller);ui.show();
   check(spinner(ui,"topology").getSelectedItemPosition()==3&&spinner(ui,"execution").getSelectedItemPosition()==2&&spinner(ui,"entry").getSelectedItemPosition()==1&&spinner(ui,"entryMode").getSelectedItemPosition()==2,"Speed Lab replaced saved external entry/mode/Compare defaults");
   spinner(ui,"scope").setSelection(1);check(spinner(ui,"execution").getVisibility()==android.view.View.VISIBLE,"External Speed Lab hides execution choices");
   spinner(ui,"execution").setSelection(java.util.Arrays.asList("local","server","auto").indexOf(requested));check(runButton(ui).performClick(),"Actual external Run callback missing");
   spinner(ui,"execution").setSelection(0);LayeredVpnService.quiesce.accept(null);waitFor(()->AndroidSpeedLab.pending!=null,"Temporary external UI did not reach measurement");
   AndroidStandardExitRuntime runtime=AndroidRuntimeRegistry.instance.standardExit;
   check(runtime.execution.equals(requested)&&runtime.selected.equals(requested.equals("auto")?"server":requested)&&AndroidHomeStateStore.current.activeEntryMode.equals("reality-xhttp"),"Actual Speed Lab Run substituted Local or a different entry mode");
   AndroidSpeedLab.drained(false);waitFor(()->!f.controller.isRunning(),"UI external cleanup never finished");f.originalRestored();check(saved.equals(android.content.Context.speedPreferences),"Temporary external choices rewrote saved path");android.app.AlertDialog.last.dismiss();
  }
  Fixture invalid=new Fixture(root,"router","external");invalid.request.execution="auto";invalid.request.externalDirect=true;invalid.start();check(invalid.result.error!=null&&LayeredVpnService.quiesce==null&&RuntimeBoundary.stops==0&&AndroidHomeStateStore.current.sessionId.equals(invalid.originalSession),"Direct Tor comparison without a private entry stopped the original path");
 }
 @SuppressWarnings("unchecked") static List<AndroidStandardExitStore.Entry> ordinaryChoices(AndroidSpeedLabDialog ui)throws Exception{var field=AndroidSpeedLabDialog.class.getDeclaredField("ordinaryEntryValues");field.setAccessible(true);return (List<AndroidStandardExitStore.Entry>)field.get(ui);}
 static void ordinaryUI(Path root)throws Exception{
  Fixture f=new Fixture(root,"router","external");List<String> protocols=List.of("wireguard","amneziawg","socks5","http","https","shadowsocks","hysteria2","openvpn");AndroidStandardExitStore.Entry saved=null;
  for(String protocol:protocols){var value=f.ordinary(protocol,protocol.equals("socks5")?f.first.id:"ordinary-"+protocol);if(protocol.equals("socks5"))saved=value;}
  JSONObject profiles=new JSONObject();JSONArray modes=new JSONArray();for(String mode:List.of("wg","max-quic-awg")){profiles.put(mode,new JSONObject());modes.put(new JSONObject().put("id",mode).put("name",mode));}Files.writeString(f.first.file.toPath(),new JSONObject().put("profiles",profiles).put("modes",modes).toString());
  AndroidConnectionProfileStore.saved=new AndroidConnectionProfileStore.ExternalSelection(null,AndroidStandardExitStore.copy(saved),AndroidStandardExitStore.copy(f.external),"socks5","local");android.content.Context.speedPreferences.put("selected_kind","external");android.content.Context.speedPreferences.put("selected_id",f.external.id);Map<String,String> preferences=new HashMap<>(android.content.Context.speedPreferences);
  AndroidSpeedLabDialog ui=new AndroidSpeedLabDialog(f.activity,f.nodes,f.connection,f.controller);ui.show();spinner(ui,"scope").setSelection(1);List<AndroidStandardExitStore.Entry> choices=ordinaryChoices(ui);
  check(choices.size()==8&&spinner(ui,"entry").getAdapter().getCount()==11&&spinner(ui,"entry").getSelectedItemPosition()>=3&&spinner(ui,"entryMode").getAdapter().getCount()==1&&spinner(ui,"execution").getAdapter().getCount()==1,"actual Speed Lab picker lost ordinary protocols or collapsed the typed colliding ID");
  spinner(ui,"entry").setSelection(1);check(spinner(ui,"entryMode").getAdapter().getCount()==2&&spinner(ui,"execution").getAdapter().getCount()==3,"same-ID private Router choice inherited ordinary modes/execution");
  for(String protocol:protocols){int index=-1;for(int i=0;i<choices.size();i++)if(choices.get(i).protocol.equals(protocol))index=i;check(index>=0,"ordinary transport absent from picker: "+protocol);var expected=choices.get(index);spinner(ui,"entry").setSelection(3+index);
   check(spinner(ui,"entryMode").getAdapter().getCount()==1&&spinner(ui,"entryMode").getSelectedItemPosition()==0&&spinner(ui,"execution").getAdapter().getCount()==1&&spinner(ui,"execution").getSelectedItemPosition()==0,"ordinary picker retained Router modes or Server/Compare: "+protocol);check(runButton(ui).performClick(),"ordinary Speed Lab Run is not wired");
   spinner(ui,"entry").setSelection(1);LayeredVpnService.quiesce.accept(null);waitFor(()->AndroidSpeedLab.pending!=null,"ordinary picker did not start measurement");var actual=AndroidRuntimeRegistry.instance.standardExit.capturedOrdinaryEntry(AndroidHomeStateStore.current);
   check(actual!=null&&actual.id.equals(expected.id)&&actual.protocol.equals(protocol)&&actual.secret.equals(expected.secret)&&AndroidHomeStateStore.current.activeEntryMode.equals(AndroidExternalPolicy.protocol(protocol)),"ordinary UI choice changed after capture or used colliding private source");
   AndroidSpeedLab.drained(false);waitFor(()->!f.controller.isRunning(),"ordinary UI cleanup did not finish");f.originalRestored();check(preferences.equals(android.content.Context.speedPreferences),"ordinary temporary picker changed saved selection");
  }
  android.app.AlertDialog.last.dismiss();
 }
 static final List<String> IMPORTED=List.of("wireguard","amneziawg","socks5","http","https","shadowsocks","hysteria2","openvpn");
 static void importedMatrix(Path root)throws Exception{
  for(String protocol:IMPORTED)for(String original:List.of("router","multihop","external-openvpn","external-tor-bridge","imported")){
   Fixture f=new Fixture(root,original.equals("imported")?"router":original,"multihop");f.importedTemporary(protocol);if(original.equals("imported"))f.importedOriginal(protocol);
   String captured=AndroidStandardExitStore.snapshot(f.request.ordinaryEntry),last=Files.readString(f.last.file.toPath());android.content.Context.speedPreferences.put("selected_mode","smart-auto");android.content.Context.speedPreferences.put("killswitch","on");android.content.Context.speedPreferences.put("dns","home-adguard");Map<String,String> prefs=new HashMap<>(android.content.Context.speedPreferences);
   f.start();check(RuntimeBoundary.stops==0&&AndroidHomeStateStore.current.sessionId.equals(f.originalSession),"imported test stopped original before quiescence");f.request.ordinaryEntry.secret="later caller edit";f.request.exitMode="wg";f.request.execution="auto";Files.writeString(f.first.file.toPath(),"unrelated colliding Router source");f.quiesce();waitFor(()->AndroidSpeedLab.pending!=null,"imported path did not reach real meter: "+protocol+" "+f.result.error);
   var active=AndroidRuntimeRegistry.instance.multihop.capturedOrdinaryEntry(AndroidHomeStateStore.current);check(active!=null&&captured.equals(AndroidStandardExitStore.snapshot(active))&&AndroidHomeStateStore.current.runtimeMode.equals("reality-vision")&&AndroidHomeStateStore.current.activeExitId.equals(f.last.id)&&AndroidRuntimeRegistry.instance.multihop.execution.equals("local"),"imported run changed captured credentials/graph/execution");
   AndroidSpeedLab.drained(false);f.complete();check(f.result.error==null&&f.result.result!=null&&AndroidNativeHopMeasurement.starts==1,"imported native graph lost measurement: "+protocol+"/"+original+" "+f.result.error);f.originalRestored();check(last.equals(Files.readString(f.last.file.toPath()))&&captured.equals(AndroidStandardExitStore.snapshot(AndroidStandardExitStore.saved.get(f.first.id)))&&prefs.equals(android.content.Context.speedPreferences),"temporary imported graph rewrote credentials or saved policy/selection");
   check(RuntimeBoundary.starts==(original.startsWith("external")?2:1),"restoration reran Compare or selected a new imported graph");
  }
 }
 @SuppressWarnings("unchecked") static void importedUI(Path root)throws Exception{
  Fixture f=new Fixture(root,"router","multihop");f.pairedFinal();for(String protocol:IMPORTED)f.ordinary(protocol,protocol.equals("socks5")?f.first.id:"imported-"+protocol);
  AndroidSpeedLabDialog ui=new AndroidSpeedLabDialog(f.activity,f.nodes,f.connection,f.controller);ui.show();spinner(ui,"scope").setSelection(1);spinner(ui,"topology").setSelection(2);spinner(ui,"exit").setSelection(2);
  List<AndroidStandardExitStore.Entry> choices=ordinaryChoices(ui);check(choices.size()==8&&spinner(ui,"entry").getAdapter().getCount()==11,"paired final picker omitted imported entries or admitted Tor");
  for(String protocol:IMPORTED){int index=-1;for(int i=0;i<choices.size();i++)if(choices.get(i).protocol.equals(protocol))index=i;check(index>=0,"missing imported picker protocol "+protocol);var expected=choices.get(index);spinner(ui,"entry").setSelection(3+index);
   check(spinner(ui,"entryMode").getAdapter().getCount()==1&&spinner(ui,"entryMode").getSelectedItemPosition()==0&&spinner(ui,"execution").getAdapter().getCount()==1&&spinner(ui,"execution").getSelectedItemPosition()==0,"imported UI offered non-Local or replaced entry protocol");
   List<NativeSingBoxController.ModeInfo> modes=(List<NativeSingBoxController.ModeInfo>)spinner(ui,"exitMode").getTag();check(modes.size()==2&&modes.get(0).id.equals("shadowsocks")&&modes.get(1).id.equals("reality-vision"),"picker offered a transport without captured original final assets");spinner(ui,"exitMode").setSelection(1);check(runButton(ui).performClick(),"imported paired Run button is not wired");spinner(ui,"entry").setSelection(1);LayeredVpnService.quiesce.accept(null);waitFor(()->AndroidSpeedLab.pending!=null,"imported UI did not start measurement");
   var actual=AndroidRuntimeRegistry.instance.multihop.capturedOrdinaryEntry(AndroidHomeStateStore.current);check(actual!=null&&AndroidStandardExitStore.snapshot(actual).equals(AndroidStandardExitStore.snapshot(expected))&&AndroidHomeStateStore.current.runtimeMode.equals("reality-vision"),"imported picker captured a Router collision or changed after Run");AndroidSpeedLab.drained(false);waitFor(()->!f.controller.isRunning(),"imported UI cleanup did not finish");f.originalRestored();
  }
  spinner(ui,"entry").setSelection(3);Files.writeString(f.last.file.toPath(),new JSONObject().put("profiles",new JSONObject()).put("modes",new JSONArray()).put("availableFinals",new JSONArray()).toString());spinner(ui,"exit").setSelection(1);spinner(ui,"exit").setSelection(2);check(spinner(ui,"exitMode").getAdapter().getCount()==0,"unavailable final transport remained selected");int stops=RuntimeBoundary.stops;LayeredVpnService.quiesce=null;runButton(ui).performClick();check(LayeredVpnService.quiesce==null&&RuntimeBoundary.stops==stops&&!f.controller.isRunning(),"empty final picker invented default Shadowsocks and stopped original");android.app.AlertDialog.last.dismiss();
 }
 static void importedInvalid(Path root)throws Exception{
  for(String change:List.of("server","auto","wrong-entry-mode","missing-final-mode","same-id","entry-key","entry-policy","entry-removed","missing-final-assets")){
   Fixture f=new Fixture(root,"router","multihop");f.importedTemporary("socks5");if(change.equals("server")||change.equals("auto"))f.request.execution=change;
   if(change.equals("wrong-entry-mode"))f.request.entryMode="wg";if(change.equals("missing-final-mode"))f.request.exitMode="";if(change.equals("same-id")){f.request.ordinaryEntry.id=f.last.id;AndroidStandardExitStore.saved.put(f.last.id,AndroidStandardExitStore.copy(f.request.ordinaryEntry));}
   if(change.equals("entry-key"))AndroidStandardExitStore.saved.get(f.first.id).secret="replacement";if(change.equals("entry-policy"))AndroidStandardExitStore.saved.get(f.first.id).policy="replacement";if(change.equals("entry-removed"))AndroidStandardExitStore.saved.remove(f.first.id);if(change.equals("missing-final-assets"))f.request.exitMode="wg";
   f.start();check(f.result.error!=null&&f.result.result==null&&LayeredVpnService.quiesce==null&&RuntimeBoundary.stops==0&&AndroidHomeStateStore.current.sessionId.equals(f.originalSession),"invalid imported request disturbed original: "+change);
  }
  for(String phase:List.of("quiesce","permission"))for(String change:List.of("entry-key","entry-policy","entry-removed","final")){
   Fixture f=new Fixture(root,"router","multihop");f.importedTemporary("socks5");if(phase.equals("permission"))android.net.VpnService.needsPermission=true;f.start();if(phase.equals("permission")){f.quiesce();waitFor(()->f.connection.isPermissionPending()&&f.activity.permissionRequest!=0,"imported permission not requested");}
   if(change.equals("entry-key"))AndroidStandardExitStore.saved.get(f.first.id).secret="replacement";if(change.equals("entry-policy"))AndroidStandardExitStore.saved.get(f.first.id).policy="replacement";if(change.equals("entry-removed"))AndroidStandardExitStore.saved.remove(f.first.id);if(change.equals("final"))Files.writeString(f.last.file.toPath(),"replacement final credentials");
   if(phase.equals("quiesce"))f.quiesce();else{android.net.VpnService.needsPermission=false;f.connection.onActivityResult(f.activity.permissionRequest,Activity.RESULT_OK);}f.complete();check(f.result.error!=null&&f.result.result==null&&AndroidSpeedLab.starts==0,"changed imported permission/quiesce source reached meter");if(phase.equals("quiesce"))check(RuntimeBoundary.stops==0&&AndroidHomeStateStore.current.sessionId.equals(f.originalSession),"quiescing source change stopped original");else f.originalRestored();
  }
  for(String change:List.of("key","policy","kind","execution")){
   Fixture f=new Fixture(root,"router","multihop");f.importedTemporary("socks5");RuntimeBoundary.afterImportedProof=()->{var runtime=AndroidRuntimeRegistry.instance.multihop;if(change.equals("key"))runtime.ordinaryEntry.secret="substituted native key";if(change.equals("policy"))runtime.ordinaryEntry.policy="substituted native DNS";if(change.equals("kind"))runtime.ordinaryEntry=null;if(change.equals("execution"))runtime.selected="server";};f.start();f.quiesce();f.complete();check(f.result.error!=null&&AndroidSpeedLab.starts==0,"substituted imported native receipt reached meter: "+change);f.originalRestored();
  }
  for(String phase:List.of("http","hops")){
   Fixture f=new Fixture(root,"router","multihop");f.importedTemporary("socks5");if(phase.equals("hops"))AndroidNativeHopMeasurement.hold=true;f.start();f.quiesce();waitFor(()->AndroidSpeedLab.pending!=null,"changed-final fixture did not measure");if(phase.equals("hops")){AndroidSpeedLab.drained(false);waitFor(()->AndroidNativeHopMeasurement.pending!=null,"changed-final fixture did not probe native hops");}Files.writeString(f.last.file.toPath(),"changed final credentials/policy");if(phase.equals("hops"))AndroidNativeHopMeasurement.drained(false);else AndroidSpeedLab.drained(false);f.complete();check(f.result.error!=null&&f.result.result==null,"changed final source retained a measurement: "+phase);f.originalRestored();
  }
  for(String source:List.of("entry-key","entry-policy","entry-removed","final","restored-key")){
   Fixture f=new Fixture(root,"router","multihop");f.importedTemporary("openvpn");f.importedOriginal("socks5");f.start();f.quiesce();waitFor(()->AndroidSpeedLab.pending!=null,"imported original mutation fixture did not measure");if(source.equals("entry-key"))AndroidStandardExitStore.saved.get(f.original.id).secret="changed original key";if(source.equals("entry-policy"))AndroidStandardExitStore.saved.get(f.original.id).policy="changed original DNS/kill switch";if(source.equals("entry-removed"))AndroidStandardExitStore.saved.remove(f.original.id);if(source.equals("final"))Files.writeString(f.last.file.toPath(),"changed original final");if(source.equals("restored-key"))RuntimeBoundary.afterRestoredProof=()->AndroidRuntimeRegistry.instance.multihop.ordinaryEntry.secret="substituted restored key";AndroidSpeedLab.drained(false);f.complete();check(f.result.error!=null&&f.result.result==null&&RuntimeBoundary.restores==(source.equals("restored-key")?1:0),"changed imported original restored or retained score: "+source);
  }
 }
 static void importedCancellation(Path root)throws Exception{
  for(String phase:List.of("quiesce","permission","connect","http","hops","cleanup","restore")){
   Fixture f=new Fixture(root,"router","multihop");f.importedTemporary("socks5");if(phase.equals("permission"))android.net.VpnService.needsPermission=true;if(phase.equals("connect"))RuntimeBoundary.holdConnect=true;if(phase.equals("hops"))AndroidNativeHopMeasurement.hold=true;f.start();if(!phase.equals("quiesce"))f.quiesce();
   if(phase.equals("permission"))waitFor(()->f.connection.isPermissionPending()&&f.activity.permissionRequest!=0,"imported cancellation permission missing");else if(phase.equals("connect"))waitFor(()->RuntimeBoundary.pendingConnect!=null,"imported cancellation native start missing");else if(!phase.equals("quiesce")){waitFor(()->AndroidSpeedLab.pending!=null,"imported cancellation meter missing");if(phase.equals("cleanup")){RuntimeBoundary.holdStop=true;RuntimeBoundary.stopEntered=false;}if(phase.equals("restore"))RuntimeBoundary.holdRestore=true;if(List.of("hops","cleanup","restore").contains(phase))AndroidSpeedLab.drained(false);if(phase.equals("hops"))waitFor(()->AndroidNativeHopMeasurement.pending!=null,"imported native hops missing");if(phase.equals("cleanup"))waitFor(()->RuntimeBoundary.stopEntered,"imported cleanup missing");if(phase.equals("restore"))waitFor(()->RuntimeBoundary.pendingRestore!=null,"imported restore missing");}
   if(phase.equals("permission"))android.net.VpnService.needsPermission=false;f.controller.cancel();if(phase.equals("quiesce"))f.quiesce();if(phase.equals("http"))AndroidSpeedLab.drained(true);if(phase.equals("hops"))AndroidNativeHopMeasurement.drained(true);if(phase.equals("cleanup")){RuntimeBoundary.holdStop=false;RuntimeBoundary.stopRelease.countDown();}if(phase.equals("restore")){RuntimeBoundary.holdRestore=false;RuntimeBoundary.pendingRestore.run();}f.complete();check(f.result.error!=null&&f.result.result==null,"cancelled imported test retained result: "+phase);if(!phase.equals("quiesce"))f.originalRestored();else check(AndroidHomeStateStore.current.sessionId.equals(f.originalSession)&&RuntimeBoundary.stops==0,"cancel before quiesce replaced original");
  }
  Fixture newer=new Fixture(root,"router","multihop");newer.importedTemporary("socks5");newer.start();newer.quiesce();waitFor(()->AndroidSpeedLab.pending!=null,"newer-owner fixture did not measure");AndroidHomeStateStore.begin("new-user","wg","","new-node","","");AndroidHomeStateStore.proved();String session=AndroidHomeStateStore.current.sessionId;AndroidSpeedLab.drained(false);newer.complete();check(newer.result.error!=null&&newer.result.result==null&&RuntimeBoundary.restores==0&&AndroidHomeStateStore.current.sessionId.equals(session)&&AndroidHomeStateStore.current.connected,"imported cleanup replaced newer user connection");
 }
 static AndroidNodeStore.ChainCapture orderedOriginal(Fixture f)throws Exception{
  return orderedOriginal(f,List.of("wg","wg","shadowsocks"));
 }
 static AndroidNodeStore.ChainCapture orderedOriginal(Fixture f,List<String> modes)throws Exception{
  AndroidNodeStore.ChainCapture source=new AndroidNodeStore.ChainCapture(List.of(f.original,f.first,f.last),modes);
  AndroidNodeStore.active=f.last.id;AndroidNodeChainRuntime runtime=AndroidRuntimeRegistry.instance.nodeChain;runtime.begin(source);AndroidHomeStateStore.proved();f.originalSession=AndroidHomeStateStore.current.sessionId;f.raw="node-chain";return source;
 }
 static void orderedRestoration(Path root)throws Exception{
  for(List<String> modes:List.of(List.of("wg","wg","shadowsocks"),List.of("awg2-fast","awg2-strong","shadowsocks"),List.of("awg2-strong","wg","shadowsocks")))for(String target:List.of("router","multihop","external","system-direct"))for(boolean cancel:new boolean[]{false,true}){
   Fixture f=new Fixture(root,"node-chain",target);var captured=orderedOriginal(f,modes);var originalPreferences=new HashMap<>(android.content.Context.speedPreferences);
   try{
    f.start();f.quiesce();waitFor(()->AndroidSpeedLab.pending!=null,"ordered original never reached temporary measurement");
    check(!AndroidRuntimeRegistry.instance.nodeChain.active&&RuntimeBoundary.stops==1,"ordered original native owner did not drain before temporary measurement");
    if(cancel){f.controller.cancel();AndroidSpeedLab.drained(true);}else f.measured();f.complete();
    var home=AndroidHomeStateStore.current;check(home.connected&&home.pathProof.equals("passed")&&home.logicalMode.equals("node-chain")&&!home.sessionId.equals(f.originalSession),"ordered original lacked fresh restored native proof");
    check(AndroidRuntimeRegistry.instance.nodeChain.restoredSource==captured&&RuntimeBoundary.restores==1&&home.activeNodeId.equals(captured.control.id)&&home.activeChain.equals(AndroidNodeChainRuntime.chain(captured)),"ordered restoration substituted original source, order, final or modes");
    check(cancel?f.result.error!=null:f.result.error==null,"ordered restoration changed temporary result/cancellation");
    check(f.last.id.equals(AndroidNodeStore.active)&&originalPreferences.equals(android.content.Context.speedPreferences),"temporary ordered restoration rewrote saved choices");
   }finally{AndroidNodeStore.active=null;AndroidRuntimeRegistry.instance.nodeChain.active=false;AndroidHomeStateStore.off();}
  }
  for(String fault:List.of("before-capture","before-stop","owner-before-stop","middle-after-stop","permission","replacement-source","new-stop")){
   Fixture f=new Fixture(root,"node-chain","router");var captured=orderedOriginal(f);
   try{
    if(fault.equals("before-capture"))Files.writeString(f.first.file.toPath(),"replaced original middle before capture");
    f.start();
    if(fault.equals("before-capture")){f.complete();check(f.result.error!=null&&RuntimeBoundary.stops==0,"ordered restore capture read today's replacement source");continue;}
    waitFor(()->LayeredVpnService.quiesce!=null||f.result.count>0,"ordered source was not captured before fault injection");
    if(fault.equals("before-stop"))Files.writeString(f.first.file.toPath(),"replaced original middle before stop");
    if(fault.equals("owner-before-stop"))AndroidRuntimeRegistry.instance.nodeChain.source=new AndroidNodeStore.ChainCapture(List.of(f.original,f.first,f.last),captured.modes);
    f.quiesce();
    if(fault.equals("before-stop")||fault.equals("owner-before-stop")){f.complete();check(f.result.error!=null&&RuntimeBoundary.stops==0,"ordered original stopped after source or owner replacement: "+fault);continue;}
    waitFor(()->AndroidSpeedLab.pending!=null,"ordered fault never reached measurement");
    if(fault.equals("middle-after-stop"))Files.writeString(f.first.file.toPath(),"replaced original middle after stop");
    if(fault.equals("permission"))android.net.VpnService.needsPermission=true;
    if(fault.equals("replacement-source"))RuntimeBoundary.afterRestoredProof=()->{try{AndroidRuntimeRegistry.instance.nodeChain.source=new AndroidNodeStore.ChainCapture(List.of(f.original,f.first,f.last),captured.modes);}catch(Exception e){throw new IllegalStateException(e);}};
    if(fault.equals("new-stop")){RuntimeBoundary.holdStop=true;RuntimeBoundary.stopEntered=false;f.measured();waitFor(()->RuntimeBoundary.stopEntered,"ordered temporary stop did not retain its worker");AndroidHomeStateStore.advancePathGeneration(f.activity);RuntimeBoundary.stopRelease.countDown();}else f.measured();
    f.complete();check(f.result.error!=null,"ordered restoration accepted stale original admission: "+fault);
    if(!fault.equals("replacement-source"))check(RuntimeBoundary.restores==0&&!AndroidHomeStateStore.current.connected,"ordered stale original reconnected after refusal: "+fault);
   }finally{RuntimeBoundary.stopRelease.countDown();android.net.VpnService.needsPermission=false;AndroidNodeStore.active=null;AndroidRuntimeRegistry.instance.nodeChain.active=false;AndroidHomeStateStore.off();}
  }
  for(boolean cancel:new boolean[]{false,true}){
   Fixture f=new Fixture(root,"node-chain","router");orderedOriginal(f);AndroidNodeChainRuntime.holdCapture=true;AndroidNodeChainRuntime.captureEntered=new java.util.concurrent.CountDownLatch(1);AndroidNodeChainRuntime.captureRelease=new java.util.concurrent.CountDownLatch(1);
   try{f.start();check(AndroidNodeChainRuntime.captureEntered.await(3,java.util.concurrent.TimeUnit.SECONDS),"ordered capture did not run on worker");check(f.controller.isRunning()&&!AndroidMTUMeasurementGate.held(),"pending ordered capture lost its process owner or acquired native MTU work early");
    if(cancel)f.controller.cancel();else AndroidHomeStateStore.advancePathGeneration(f.activity);
    AndroidNodeChainRuntime.captureRelease.countDown();f.complete();check(f.result.error!=null&&RuntimeBoundary.starts==0&&RuntimeBoundary.stops==0&&AndroidHomeStateStore.current.connected&&AndroidHomeStateStore.current.sessionId.equals(f.originalSession),"cancelled/replaced ordered capture started a temporary path");
   }finally{AndroidNodeChainRuntime.holdCapture=false;AndroidNodeChainRuntime.captureRelease.countDown();AndroidNodeStore.active=null;AndroidRuntimeRegistry.instance.nodeChain.active=false;AndroidHomeStateStore.off();}
  }
  {
   Fixture f=new Fixture(root,"node-chain","router");orderedOriginal(f);
   try{
    var nativeOwner=AndroidRuntimeRegistry.instance.nodeChain;
    nativeOwner.beforeCapturedDrain=()->{nativeOwner.active=false;var failed=AndroidHomeStateStore.copy();failed.connected=false;failed.phase="failed";failed.pathProof="failed";failed.activeNodeId="";failed.activeChain="";AndroidHomeStateStore.current=failed;};
    f.start();f.quiesce();f.complete();
    check(f.result.error!=null&&RuntimeBoundary.starts==0&&RuntimeBoundary.stops==0&&!nativeOwner.active,"terminal ordered owner was retried or replaced after release before captured drain");
   }finally{AndroidNodeStore.active=null;AndroidRuntimeRegistry.instance.nodeChain.active=false;AndroidHomeStateStore.off();}
  }
  // Hold the actual worker's posted UI result after its expensive validation.
  // A newer Home decision must still win when that result is finally rendered.
  for(String stage:List.of("capture","admission","restored"))for(boolean choice:new boolean[]{false,true}){
   Fixture f=new Fixture(root,"node-chain","router");orderedOriginal(f);
   android.app.Activity.queuedThread="routervpn-speedlab-ordered-"+stage;
   try{
    f.start();if(!stage.equals("capture"))f.quiesce();if(stage.equals("restored"))f.measured();
    waitFor(()->android.app.Activity.queuedAction!=null,"ordered worker did not post its held UI completion: "+stage);
    if(choice)android.content.Context.speedPreferences.put("multihop_nodes","newer saved order or Off decision");
    else if(stage.equals("restored")){AndroidHomeStateStore.begin("new-user","wg","","new-node","","");AndroidHomeStateStore.proved();}
    else AndroidHomeStateStore.advancePathGeneration(f.activity);
    String replacement=AndroidHomeStateStore.current.sessionId;
    Runnable delivery=android.app.Activity.queuedAction;android.app.Activity.queuedAction=null;android.app.Activity.queuedThread="";delivery.run();f.complete();
    check(f.result.error!=null&&f.result.result==null&&AndroidHomeStateStore.current.connected&&replacement.equals(AndroidHomeStateStore.current.sessionId),"late ordered worker result adopted or stopped a newer Home owner: "+stage);
    if(!stage.equals("restored"))check(RuntimeBoundary.starts==0&&RuntimeBoundary.stops==0,"late ordered admission stopped the original owner: "+stage);
   }finally{android.app.Activity.queuedThread="";android.app.Activity.queuedAction=null;AndroidNodeStore.active=null;AndroidRuntimeRegistry.instance.nodeChain.active=false;AndroidHomeStateStore.off();}
  }
 }
 public static void main(String[]args)throws Exception{Path root=Path.of(args[0]);matrix(root);externalUI(root);ordinaryUI(root);ordinaryRestoration(root);ordinaryRestoreChanges(root);importedMatrix(root);importedUI(root);importedInvalid(root);importedCancellation(root);exactMultihopWinner(root);exactExternalWinner(root);exactTorExecution(root);externalOriginalSources(root);cancellation(root);stale(root);multihopPins(root);permissionCapture(root);permissionSelection(root);uiCancellation(root);orderedRestoration(root);System.out.println("Shipping Android Speed Lab restoration: "+checks+" checks; original native sources before capture and stop,captured winners,all-member ordered restores,40 ordinary and 40 imported paired graph restores,8-protocol typed pickers,cleanup/permission source changes,saved/test selection separation,cancellation phases and newer-user ownership");}
}
'''

def replace_class(text, name, replacement):
    start=text.index('final class '+name+' {')
    end=text.find('\nfinal class ',start+1)
    if end<0:end=len(text)
    return text[:start]+replacement+text[end:]

def sources():
    ui=dict(P.T.UI)
    ui['android/app/Activity.java']=ui['android/app/Activity.java'].replace('public void runOnUiThread(Runnable action){action.run();}', 'public static volatile String queuedThread="";public static volatile Runnable queuedAction;public void runOnUiThread(Runnable action){if(Thread.currentThread().getName().equals(queuedThread)){if(queuedAction!=null)throw new AssertionError("second queued UI completion");queuedAction=action;}else action.run();}')
    ui['android/content/Context.java']=ui['android/content/Context.java'].replace('public SharedPreferences getSharedPreferences(String name,int mode){return (key,fallback)->fallback;}', 'public static final java.util.Map<String,String> speedPreferences=new java.util.HashMap<>();public SharedPreferences getSharedPreferences(String name,int mode){return new SharedPreferences(){public String getString(String key,String fallback){return speedPreferences.getOrDefault(key,fallback);}public java.util.Map<String,?> getAll(){return new java.util.LinkedHashMap<>(speedPreferences);}};}')
    ui['android/content/SharedPreferences.java']='package android.content;public interface SharedPreferences{String getString(String key,String fallback);java.util.Map<String,?> getAll();}'
    # AdapterView.INVALID_POSITION represents an unavailable saved selection;
    # it must stay unselected instead of implicitly choosing another entry mode.
    ui['android/widget/Spinner.java']=ui['android/widget/Spinner.java'].replace('if(value<0||adapter==null||value>=adapter.getCount())','if(value < -1||adapter==null||value>=adapter.getCount())').replace('if(listener!=null)listener.onItemSelected(this,null,position,position);','if(listener!=null){if(position<0)listener.onNothingSelected(this);else listener.onItemSelected(this,null,position,position);}')
    ui['android/os/Bundle.java']=ui['android/os/Bundle.java'][:-1]+'public void putStringArrayList(String k,java.util.ArrayList<String> v){values.put(k,v);}public java.util.ArrayList<String> getStringArrayList(String k){return (java.util.ArrayList<String>)values.get(k);}public boolean containsKey(String k){return values.containsKey(k);}}'

    ui['android/graphics/Color.java']='package android.graphics;public final class Color{public static final int WHITE=-1;public static int rgb(int r,int g,int b){return r*65536+g*256+b;}}'
    ui['android/view/Gravity.java']='package android.view;public final class Gravity{public static final int CENTER_VERTICAL=16;}'
    ui['android/view/View.java']=ui['android/view/View.java'][:-1]+'public static final int VISIBLE=0,GONE=8;private Object tag;public void setTag(Object v){tag=v;}public Object getTag(){return tag;}private int visibility;public void setVisibility(int v){visibility=v;}public int getVisibility(){return visibility;}public void setBackgroundColor(int c){} }'
    ui['android/widget/TextView.java']=ui['android/widget/TextView.java'][:-1]+'public void setTextIsSelectable(boolean v){}public void setHintTextColor(int c){} }'
    ui['android/widget/LinearLayout.java']=ui['android/widget/LinearLayout.java'].replace('public static final int VERTICAL=1;','public static final int VERTICAL=1,HORIZONTAL=0;public void setGravity(int g){}').replace('public LayoutParams(int width,int height){}','public LayoutParams(int width,int height){}public LayoutParams(int width,int height,float weight){}')
    ui['android/widget/CheckBox.java']=ui['android/widget/CheckBox.java'][:-1]+'public interface OnCheckedChangeListener{void onChanged(CheckBox c,boolean v);}public void setOnCheckedChangeListener(OnCheckedChangeListener l){} }'
    ui['android/widget/ArrayAdapter.java']=ui['android/widget/ArrayAdapter.java'].replace('public void setDropDownViewResource', 'public ArrayAdapter(android.content.Context c,int layout,java.util.List<T> source){values=(T[])source.toArray();}public void setDropDownViewResource')
    ui['android/widget/SeekBar.java']='package android.widget;public final class SeekBar extends android.view.View{int value;OnSeekBarChangeListener listener;public SeekBar(android.content.Context c){super(c);}public void setMax(int v){}public void setProgress(int v){value=v;if(listener!=null)listener.onProgressChanged(this,v,false);}public int getProgress(){return value;}public void setOnSeekBarChangeListener(OnSeekBarChangeListener l){listener=l;}public interface OnSeekBarChangeListener{void onStartTrackingTouch(SeekBar b);void onStopTrackingTouch(SeekBar b);void onProgressChanged(SeekBar b,int p,boolean u);}}'
    ui['android/app/AlertDialog.java']=ui['android/app/AlertDialog.java'].replace('public void dismiss(){','public boolean isShowing(){return showing;}public void dismiss(){')
    boundaries=P.BOUNDARIES.replace('String id="saved-exit",protocol','String name="Saved exit",id="saved-exit",protocol')
    for name in ('AndroidHomeStateStore','AndroidModeOrchestrator','AndroidMultihopRuntime','AndroidStandardExitRuntime','AndroidConnectionProfileStore','AndroidNodeChainRuntime'):
        boundaries=replace_class(boundaries,name,'')
    boundaries=boundaries.replace('static void compile(AndroidStandardExitStore.Entry e,JSONObject b,String mode,String execution){requireEntry(e);', 'static void compile(AndroidStandardExitStore.Entry e,JSONObject b,String mode,String execution){if(b.has("availableFinals")&&!b.optJSONArray("availableFinals").toString().contains("\\\""+mode+"\\\""))throw new IllegalArgumentException("original final service unavailable");requireEntry(e);')
    boundaries=boundaries.replace('return busy;','return busy||RuntimeBoundary.stopping||AndroidHomeStateStore.current.connected||AndroidHomeStateStore.current.phase.equals("connecting");')
    native=(JAVA/'NativeSingBoxController.java').read_text()
    predicates=[]
    for name in ('nativeMultihopEntry','nativeWireGuardFamily','nativeNaiveFamily','nativePQFamily'):
        predicates.append(re.findall(r'(?ms)^    static boolean '+name+r'\(String mode\) \{\n.*?^    \}',native)[0])
    composite=re.findall(r'(?ms)^    static boolean isMode\(String mode\) \{\n.*?^    \}',(JAVA/'AndroidNativeCompositeProfile.java').read_text())[0]
    speed=(JAVA/'AndroidSpeedLab.java').read_text();duration=speed[speed.index('    static final class DurationPolicy'):speed.index('    static final class Latency')]
    boundaries=boundaries.replace(' // PRODUCTION_TRANSPORT_PREDICATES','\n'.join(predicates)).replace(' // PRODUCTION_COMPOSITE_PREDICATE',composite)+OWNERS+METERS.replace(' // PRODUCTION_DURATION',duration)
    return ui,boundaries

def main():
    jar=Path(os.environ.get('ANDROID_JSON_JAR','/usr/share/java/com.android.json.jar'))
    ui,boundaries=sources()
    with tempfile.TemporaryDirectory(prefix='routervpn-speed-restore-') as directory:
        root=Path(directory)
        for name,body in ui.items():
            p=root/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_text(body)
        app=root/'com/eabusham/routervpn';app.mkdir(parents=True)
        (app/'Boundaries.java').write_text(boundaries);(app/'SpeedLabRestoreTest.java').write_text(HARNESS)
        for name in ('AndroidConnectionSelection.java','AndroidUnifiedConnectionController.java','AndroidSpeedLabController.java','AndroidMTUMeasurementGate.java','AndroidSpeedLabDialog.java'):
            shutil.copyfile(JAVA/name,app/name)
        compile=['javac','--release','17','-encoding','UTF-8','-proc:none','-cp',str(jar),'-d',str(root/'classes'),*map(str,root.rglob('*.java'))]
        run=['java','-cp',os.pathsep.join((str(root/'classes'),str(jar))),'com.eabusham.routervpn.SpeedLabRestoreTest',str(root/'data')]
        (root/'data').mkdir()
        subprocess.run(compile,check=True,timeout=45);subprocess.run(run,check=True,timeout=35)
        cases=(
            ('AndroidSpeedLabController.java','&&connection.capturedCleanupPending(home,topology)','','terminal ordered cleanup was retried'),
            ('AndroidUnifiedConnectionController.java','AndroidConnectionSelection.requireCurrent(activity,nodeStore,point.orderedCapture.selection);return true;','return true;','late original saved selection'),
            ('AndroidSpeedLabController.java','if(orderedCaptureCancelled){callback.finished(null,cancelled());return;}','','cancelled ordered capture'),
            ('AndroidSpeedLabController.java','if(!connection.pathCurrent(expected)||!connection.restoreChoiceCurrent(originalCapture)){callback.finished(null,new IllegalStateException("A newer connection decision cancelled the ordered test capture."));return;}','','late ordered capture Home epoch'),
            ('AndroidSpeedLabController.java','if(!valid||!connection.pathCurrent(original.home)||!connection.restoreChoiceCurrent(original))','if(!valid||!connection.restoreChoiceCurrent(original))','late ordered admission Home epoch'),
            ('AndroidSpeedLabController.java','if(!proved||!connection.pathCurrent(observed)||!connection.restoreChoiceCurrent(original))','if(!proved||!connection.restoreChoiceCurrent(original))','late ordered restoration Home epoch'),
            ('AndroidUnifiedConnectionController.java','runtime.nodeChain.restore(point.orderedCapture,idle,','runtime.nodeChain.connect(point.orderedCapture.source,idle,','retained original ordered replay'),
            ('AndroidUnifiedConnectionController.java','runtime.nodeChain.restoredMatches(point.orderedCapture)','true','fresh ordered native source owner'),
            ('AndroidUnifiedConnectionController.java','runtime.nodeChain.captureCurrent(point.orderedCapture)','true','original ordered native owner before stop'),
            ('AndroidSpeedLabDialog.java','cancel.setOnClickListener(v->{controller.cancel();','cancel.setOnClickListener(v->{;','Cancel button'),
            ('AndroidSpeedLabDialog.java','dialog.setOnDismissListener(d->{if(controller.isRunning())controller.cancel();});','dialog.setOnDismissListener(d->{});','dialog cancellation'),
            ('AndroidSpeedLabController.java','if(!originalSuspended||original==null||!original.connected())','if(true)','original restore'),
            ('AndroidSpeedLabController.java','meter.cancel();return;','return;','HTTP cancellation'),
            ('AndroidSpeedLabController.java','nativeHopMeter.cancel();return;','return;','native cancellation'),
            ('AndroidUnifiedConnectionController.java','point.home.runtimeMode,point.home.logicalMode,point.home.fallback','"wg",point.home.logicalMode,point.home.fallback','exact original transport'),
            ('AndroidUnifiedConnectionController.java','if(!file.getValue().equals(', 'if(false&&!file.getValue().equals(', 'changed original node'),
            ('AndroidSpeedLabController.java','if(!proved||!connection.pathCurrent(observed)||!connection.restoreChoiceCurrent(original))','if(false)','fresh restoration owner'),
            ('AndroidUnifiedConnectionController.java','multihop.restoreCaptured(point.entry,point.exit,point.multihopCapture,idle,','multihop.connect(point.entry,point.exit,point.home.runtimeMode,point.execution,point.home.activeEntryMode,','captured original winner'),
            ('AndroidUnifiedConnectionController.java','multihop.captureCurrent(point.multihopCapture)','true','original Server pin owner'),
            ('AndroidUnifiedConnectionController.java','multihop.restoredMatches(point.multihopCapture,point.entry,point.exit,now)','true','restored Server pin owner'),
            ('AndroidUnifiedConnectionController.java','execution=runtime.standardExit.capturedRequestedExecution(home);selectedExecution=runtime.standardExit.capturedExternalExecution(home);','execution="local";selectedExecution="local";','captured Tor Server execution'),
            ('AndroidUnifiedConnectionController.java','ordinaryEntry=runtime.standardExit.capturedOrdinaryEntry(home);','ordinaryEntry=null;','captured ordinary source kind'),
            ('AndroidUnifiedConnectionController.java','if("external".equals(point.topology))validateExternalRestoreSource(point);','','original native external source'),
            ('AndroidUnifiedConnectionController.java','validateRestorePoint(point);\n            runtime.standardExit.requireMeasurementSource(point.externalSource);','runtime.standardExit.requireMeasurementSource(point.externalSource);','saved source before original stop'),
            ('AndroidUnifiedConnectionController.java','runtime.standardExit.requireMeasurementSource(point.externalSource);','','native owner before original stop'),
            ('AndroidUnifiedConnectionController.java','&&point.home.activeEntryId.equals(point.entry.id)&&captured.routerEntry.equals(saved.file.getCanonicalFile())','&&point.home.activeEntryId.equals(point.entry.id)','same-ID private file relink'),
            ('Boundaries.java','captured!=activeMeasurementSource||','','retained native source identity'),
            ('AndroidUnifiedConnectionController.java','if(point.ordinaryEntry==null?restored!=null:restored==null||!point.ordinaryEntryDigest.equals(externalDigest(restored)))return false;','','restored ordinary source identity'),
            ('AndroidSpeedLabController.java','connection.connectImportedMultihop(request.ordinaryEntry,request.exit,request.exitMode,request.execution,bridge);','connection.connectMultihop(request.entry,request.exit,request.exitMode,request.execution,request.entryMode,bridge);','temporary imported native dispatch'),
            ('AndroidSpeedLabController.java','AndroidImportedRouterPath.compile(captured.ordinaryEntry,AndroidImportedRouterPath.finalBundle(captured.exit.file),captured.exitMode,captured.execution);','','imported compiler before original stop'),
            ('AndroidSpeedLabController.java','return connection.capturedOrdinaryEntryMatches(state,q.ordinaryEntry);','return true;','imported native credential receipt'),
            ('AndroidSpeedLabController.java','try{for(Map.Entry<File,String> source:capturedFiles.entrySet())if(!source.getValue().equals(digest(source.getKey())))return false;}catch(Exception changed){return false;}','','final source during measurement'),
            ('AndroidUnifiedConnectionController.java','if(expected!=null&&"multihop".equals(owner.logicalMode)&&(!"local".equals(multihop.activeExecution())||!"local".equals(multihop.activeSelectedExecution())))return false;','','exact imported Local runtime'),
            ('AndroidSpeedLabDialog.java','AndroidImportedRouterPath.compile(ordinary,bundle,candidate,"local");','','picker original final capabilities'),
        )
        for filename,old,new,label in cases:
            path=app/filename;source=path.read_text();assert source.count(old)==1,label
            path.write_text(source.replace(old,new));subprocess.run(compile,check=True,timeout=45,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            result=subprocess.run(run,capture_output=True,text=True,timeout=35)
            assert result.returncode!=0 and 'AssertionError' in result.stderr,label+' negative control escaped'
            path.write_text(source)
        print(f'Android connected Speed Lab negative controls: {len(cases)} rejected')

if __name__=='__main__':main()
