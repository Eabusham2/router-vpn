#!/usr/bin/env python3
"""Compose the shipping temporary supervisor, runtime, session and native host.

The candidate worker/result parser/MTU lease also run unchanged. OS, native
handles, source compiler, cohort callback and proposal persistence are explicit
boundaries; their complete source/store/MTU adapters have independent gates.
"""
from pathlib import Path
import importlib.util
import os
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('preparation_owner_boundaries', ROOT / 'android/test_android_node_chain_runtime.py')
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)
APP = base.APP
NATIVE = base.NATIVE
SOURCES = dict(base.SOURCES)
SOURCES[APP + 'AndroidMTUSession.java'] = SOURCES[APP + 'AndroidMTUSession.java'].replace(
    'throw new IllegalStateException("No ordered candidate MTU proof in this boundary");',
    'if(!AndroidMTUMeasurementGate.owns(lease))throw new IllegalStateException("foreign MTU hold");activateNodeChain(source);if(failure!=null)throw failure;')
SOURCES[NATIVE + 'RouterNodeChain.java'] = SOURCES[NATIVE + 'RouterNodeChain.java'][:-1] + 'public String sourceSHA256(){return "a".repeat(64);}public String configSHA256(){return "b".repeat(64);}}'
SOURCES[NATIVE + 'Libbox.java'] = SOURCES[NATIVE + 'Libbox.java'][:-1] + '''
 public static RouterNodeChainCandidateMeasurement routerNodeChainNewCandidateMeasurement(RouterNodeChain plan,CommandServer server,int prefix,String inventory,Object catalog)throws Exception{
  if(plan.server!=server||!plan.healthy())throw new IllegalStateException("foreign candidate native owner");return new RouterNodeChainCandidateMeasurement();}
 public static void routerNodeChainCloseCandidateMeasurement(RouterNodeChain plan,int prefix,String inventory)throws Exception{if(RouterNodeChainCandidateMeasurement.latest!=null)RouterNodeChainCandidateMeasurement.latest.close();}
}'''
SOURCES[NATIVE + 'RouterNodeChainCandidateMeasurement.java'] = r'''package io.nekohasekai.libbox;
import org.json.*;public final class RouterNodeChainCandidateMeasurement {
 public static volatile RouterNodeChainCandidateMeasurement latest;public static volatile boolean holdClose;public volatile int starts,closes;String request="",id="";
 public RouterNodeChainCandidateMeasurement(){latest=this;}public String captureSHA256(){return "c".repeat(64);}
 public String metadata()throws Exception{return new JSONObject().put("capture_sha256",captureSHA256()).put("source_sha256","a".repeat(64)).put("config_sha256","b".repeat(64)).put("prefix_position",0).put("prefix_id","prefix").put("targets",new JSONArray().put(new JSONObject().put("id","one").put("source_sha256","d".repeat(64))).put(new JSONObject().put("id","two").put("source_sha256","e".repeat(64)))).toString();}
 public void start(String request,String id){this.request=request;this.id=id;starts++;}public void cancel(String request){}public void drain(String request){}
 public void close()throws Exception{closes++;if(holdClose)throw new IllegalStateException("original candidate callback still running");}
 public String statusJSON()throws Exception{
  long now=System.currentTimeMillis();JSONObject distribution=new JSONObject().put("samples",50).put("min_ms",1).put("median_ms",2).put("average_ms",2).put("p90_ms",3).put("max_ms",4).put("jitter_ms",1);
  JSONObject row=new JSONObject().put("node_id",id).put("role","candidate").put("kind","tcp-connect").put("ready",true).put("benchmark",new JSONObject().put("schema",1).put("measurement","routed-tcp-connect").put("attempts",50).put("failed",0).put("distribution",distribution).put("trimmed_mean_ms",2));
  return new JSONObject().put("schema",1).put("measurement","routed-tcp-connect").put("request_id",request).put("complete",true).put("drained",true).put("stage","complete").put("failure","").put("capture_sha256",captureSHA256()).put("prefix_position",0).put("prefix_id","prefix").put("candidate_id",id).put("candidate_source_sha256",(id.equals("one")?"d":"e").repeat(64)).put("measured_at",now).put("expires_at",now+120000).put("results",new JSONArray().put(row)).toString();
 }
}'''
SOURCES[APP + 'AndroidNodeCandidateCatalog.java'] = '''package com.eabusham.routervpn;
final class AndroidNodeCandidateCatalog {
 static volatile boolean sourcesValid=true;final AndroidNodeChainSession session;final io.nekohasekai.libbox.CommandServer server;final int prefix;final String inventory="original inventory";
 static final class Row{final String id,name,input="original input";Row(String id){this.id=id;name=id;}}
 final java.util.List<Row> rows=java.util.List.of(new Row("one"),new Row("two"));
 AndroidNodeCandidateCatalog(android.content.Context context,AndroidNodeChainSession session,int prefix)throws Exception{this.session=session;this.prefix=prefix;server=session.candidateServer();}
 void requireCurrent(){try{session.requireCurrent();requireSavedSourcesCurrent();}catch(Exception stale){throw new IllegalStateException(stale);}}
 void requireSavedSourcesCurrent(){if(!sourcesValid)throw new IllegalStateException("captured saved catalog changed away and back");}
}'''
SOURCES[APP + 'AndroidNodeCandidateProfile.java'] = '''package com.eabusham.routervpn;
final class AndroidNodeCandidateProfile {
 interface SavedResultAuthority{void requireCurrent(AndroidNodeCandidateResult result)throws Exception;}
 final AndroidNodeCandidateResult result;final SavedResultAuthority authority;
 private AndroidNodeCandidateProfile(AndroidNodeCandidateResult result,SavedResultAuthority authority){this.result=result;this.authority=authority;}
 static AndroidNodeCandidateProfile captureTemporary(AndroidNodeCandidateMeasurement owner,AndroidNodeCandidateResult result,SavedResultAuthority authority)throws Exception{owner.requireResult(result);return new AndroidNodeCandidateProfile(result,authority);}
 void save()throws Exception{authority.requireCurrent(result);}
}'''
SOURCES[APP + 'AndroidExternalComparisonNetwork.java'] = '''package com.eabusham.routervpn;
final class AndroidExternalComparisonNetwork {
 static volatile AndroidExternalComparisonNetwork latest;final android.net.Network physical;volatile boolean valid=true,closed;int proved;
 AndroidExternalComparisonNetwork(android.content.Context context){physical=((android.net.ConnectivityManager)context.getSystemService(android.content.Context.CONNECTIVITY_SERVICE)).physical;latest=this;}
 void start(){}void requireBeforeStart(){requireCurrent();}void requireCurrent(){if(!valid||closed)throw new IllegalStateException("captured physical cohort changed away and back");}
 void requireProved(android.net.Network actual){requireCurrent();if(actual!=physical)throw new IllegalStateException("different native physical network");proved++;}void close(){closed=true;}
}'''

CASES = r'''
 static final class Completion implements AndroidNodeCandidatePreparation.Callback {
  final CountDownLatch done=new CountDownLatch(1);volatile List<AndroidNodeCandidatePreparation.Choice> choices;volatile Throwable failure;volatile String detail="";boolean throwsObserver;
  public void progress(String detail){this.detail=detail;}public void finished(List<AndroidNodeCandidatePreparation.Choice> value,Throwable error){choices=value;failure=error;done.countDown();if(throwsObserver)throw new IllegalStateException("disposed preparation Activity");}
  void awaitDone()throws Exception{check(done.await(30,TimeUnit.SECONDS),"temporary process owner did not deliver cleanup completion");}
 }
 static boolean activePreparation(){try{Field field=AndroidNodeCandidatePreparation.class.getDeclaredField("active");field.setAccessible(true);return field.get(null)!=null;}catch(Exception error){throw new AssertionError(error);}}
 static AndroidNodeCandidatePreparation prepare(Fixture f,Completion callback)throws Exception{
  RouterNodeChainCandidateMeasurement.latest=null;RouterNodeChainCandidateMeasurement.holdClose=false;AndroidNodeCandidateCatalog.sourcesValid=true;
  return AndroidNodeCandidatePreparation.reserve(f.service,f.runtime,f.source,AndroidHomeStateStore.snapshot(f.service),AndroidNodeChainSession.selection(f.service,f.source),0,callback);
 }
 static void retire(AndroidNodeCandidatePreparation operation)throws Exception{operation.cancelFromUser();await(()->!activePreparation(),"original preparation observer did not close");}
 static void completePreparation()throws Exception {
  try(Fixture f=new Fixture(3)){
   int history=AndroidStartupPolicy.recorded;Completion detached=new Completion(),callback=new Completion();var operation=prepare(f,detached);operation.attach(callback);operation.detach(detached);check(operation.observes(callback),"old Activity detached its replacement observer");
   check(callback.detail.contains("Waiting for Android VPN permission"),"recreated Activity lost captured waiting-permission progress");
   check(AndroidNodeCandidatePreparation.busy()&&AndroidMTUMeasurementGate.held()&&f.owner()==null,"permission capture did not retain an idle outer hold");
   operation.start();callback.awaitDone();f.drain();
   check(callback.failure==null&&callback.choices.size()==2,"temporary candidate batch did not return complete post-DOWN choices");
   check(detached.done.getCount()==1,"reattached preparation notified its abandoned Activity");
   check(!f.runtime.isActiveOrTransitioning()&&!AndroidMTUMeasurementGate.held()&&!AndroidNodeCandidateMeasurement.busy(),"temporary choices were delivered before both native owners joined");
   check(RouterNodeChainCandidateMeasurement.latest.starts==2&&AndroidExternalComparisonNetwork.latest.proved==1,"temporary candidates bypassed the real native host or complete inventory");
   check(AndroidStartupPolicy.recorded==history,"temporary candidate preparation persisted Last history");
   for(var choice:callback.choices)choice.profile.save();
   Completion recreated=new Completion();operation.attach(recreated);check(recreated.done.await(5,TimeUnit.SECONDS),"recreated Activity did not receive completed candidate choices");
   check(recreated.choices==callback.choices&&!AndroidNodeCandidatePreparation.busy()&&AndroidNodeCandidatePreparation.retained()==operation,"recreated Activity could not recover or dismiss completed candidate choices");
   AndroidNodeCandidateCatalog.sourcesValid=false;reject(()->callback.choices.get(0).profile.save(),"post-DOWN candidate ignored captured catalog changes");AndroidNodeCandidateCatalog.sourcesValid=true;
   f.connected();reject(()->callback.choices.get(0).profile.save(),"post-DOWN candidate saved after a replacement connection");f.stop();retire(operation);
  }
 }
 static void capturedPermission()throws Exception {
  for(boolean cancel:new boolean[]{true,false})try(Fixture f=new Fixture(3)){
   int created=CommandServer.created;Completion callback=new Completion();callback.throwsObserver=true;var operation=prepare(f,callback);
   if(cancel)operation.cancelFromUser();else f.service.getSharedPreferences("router-vpn-unified",0).edit().putString("mode","changed").apply();
   callback.awaitDone();await(()->!activePreparation(),"cancelled permission capture retained its observer");
   Completion late=new Completion();operation.attach(late);check(late.done.await(5,TimeUnit.SECONDS)&&late.choices.isEmpty(),"late Activity attachment lost terminal failed or empty completion");
   check(CommandServer.created==created&&!AndroidMTUMeasurementGate.held()&&!f.runtime.isActiveOrTransitioning()&&callback.choices.isEmpty(),"cancelled or stale permission capture started a native graph or leaked its lease");
   reject(operation::start,"cancelled original permission capture started later");
  }
 }
 static void failedNativeGraphJoin()throws Exception {
  try(Fixture f=new Fixture(3)){
   Completion callback=new Completion();var operation=prepare(f,callback);RouterNodeChain.configured=plan->plan.afterRun=()->plan.server.failClose=true;operation.start();
   await(()->RouterNodeChainCandidateMeasurement.latest!=null&&RouterNodeChainCandidateMeasurement.latest.closes>0,"candidate inner worker never reached native close");
   await(()->!AndroidNodeCandidateMeasurement.busy(),"candidate inner worker did not join");
   var session=f.owner();check(session!=null,"failed native graph join lost original session");var server=(CommandServer)get(f.service,"commandServer");
   await(()->server.checkedCloses>0,"temporary watcher did not reach the original failing native graph close");
   check(AndroidMTUMeasurementGate.held()&&AndroidNodeCandidatePreparation.busy()&&!server.closed&&!session.released()&&callback.done.getCount()==1,"inner candidate join released outer hold before failed graph close");
   server.failClose=false;callback.awaitDone();await(()->!AndroidMTUMeasurementGate.held(),"successful graph retry retained the original outer lease");
   check(session.released()&&server.closed&&!f.runtime.isActiveOrTransitioning(),"cleanup watcher did not retire its exact original native graph");retire(operation);
  }
 }
 static void revokedWhileCandidateDrains()throws Exception {
  try(Fixture f=new Fixture(3)){
   Completion callback=new Completion();callback.throwsObserver=true;var operation=prepare(f,callback);RouterNodeChainCandidateMeasurement.holdClose=true;operation.start();
   await(()->RouterNodeChainCandidateMeasurement.latest!=null&&RouterNodeChainCandidateMeasurement.latest.closes>0,"held candidate close was not entered");
   var session=f.owner();var server=(CommandServer)get(f.service,"commandServer");f.service.onRevoke();f.drain();
   check(AndroidMTUMeasurementGate.held()&&!server.closed&&!session.released()&&callback.done.getCount()==1,"revocation abandoned the candidate join or outer graph hold");
   RouterNodeChainCandidateMeasurement.holdClose=false;callback.awaitDone();await(()->!activePreparation(),"revoked candidate callback left its process owner behind");
   check(session.released()&&!AndroidMTUMeasurementGate.held()&&callback.choices.isEmpty(),"revoked candidate result survived failed cleanup or retained a dead lease");
  }
 }
 public static void main(String[] args)throws Exception {
  String family=args.length==0?"all":args[0];
  try {
   if(family.equals("all")||family.equals("complete"))completePreparation();
   if(family.equals("all")||family.equals("permission"))capturedPermission();
   if(family.equals("all")||family.equals("graph-join"))failedNativeGraphJoin();
   if(family.equals("all")||family.equals("revoke"))revokedWhileCandidateDrains();
   System.out.println("Android temporary candidate process owner: "+checks+" executable composed host checks passed; explicit OS/native/source boundaries.");
  } finally {RouterNodeChainCandidateMeasurement.holdClose=false;AndroidNodeCandidatePreparation.cancelActive();}
 }
}'''


def main():
    jar = Path(os.environ.get('ANDROID_JSON_JAR', '/usr/share/java/com.android.json.jar'))
    if not jar.is_file() or not shutil.which('javac'):
        raise RuntimeError('Actual JDK17 and Android JSON library required')
    with tempfile.TemporaryDirectory(prefix='routervpn-candidate-owner-') as directory:
        work = Path(directory)
        src = work / 'src'
        for path, text in SOURCES.items():
            target = src / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(text)
        app = src / APP
        names = ('AndroidHomeStateStore', 'AndroidConnectionSelection', 'AndroidNodeChainSession', 'AndroidNodeChainMTUPlatform', 'AndroidNodeChainRuntime', 'LayeredVpnService', 'AndroidMTUMeasurementGate', 'AndroidNodeCandidateMeasurement', 'AndroidNodeCandidateResult', 'AndroidNodeCandidatePreparation')
        for name in names:
            (app / (name + '.java')).write_text((base.JAVA / (name + '.java')).read_text())
        (app / 'OrderedRuntimeTest.java').write_text(base.HARNESS.split(' public static void main(String[] args)throws Exception {')[0] + CASES)
        classes = work / 'classes'
        subprocess.run(['javac', '--release', '17', '-encoding', 'UTF-8', '-proc:none', '-cp', str(jar), '-d', str(classes), *map(str, src.rglob('*.java'))], check=True, timeout=60)
        subprocess.run(['java', '-cp', os.pathsep.join((str(classes), str(jar))), 'com.eabusham.routervpn.OrderedRuntimeTest'], check=True, timeout=90)
        original = (base.JAVA / 'AndroidNodeCandidatePreparation.java').read_text()
        controls = (
            ('if(terminalCompletionReady&&callback!=null)', 'if(false&&callback!=null)', 'permission', 'late Activity attachment lost terminal failed or empty completion'),
            ('if(observer==callback){observer=null;observerVersion++;}', 'if(true){observer=null;observerVersion++;}', 'complete', 'old Activity detached its replacement observer'),
            ('boolean joined=false;', 'AndroidMTUMeasurementGate.release(lease);boolean joined=false;', 'graph-join', 'inner candidate join released outer hold before failed graph close'),
            ('network.requireProved(LayeredVpnService.prepareNodeCandidates(session,lease));', 'LayeredVpnService.prepareNodeCandidates(session,lease);', 'complete', 'temporary candidates bypassed the real native host or complete inventory'),
            ('catalog.requireSavedSourcesCurrent();', '', 'complete', 'post-DOWN candidate ignored captured catalog changes'),
            ('if(runtime.isActiveOrTransitioning()||!sameIdle(now,resultHome)||AndroidHomeStateStore.emergencyDisconnectPending(context))', 'if(false)', 'complete', 'post-DOWN candidate saved after a replacement connection'),
            ('delivered=deliverCompletion(delivered);', '', 'complete', 'recreated Activity did not receive completed candidate choices'),
        )
        for number, (before, after, family, witness) in enumerate(controls):
            if original.count(before) != 1:
                raise AssertionError('Temporary supervisor control lost exact seam: ' + before)
            out = work / ('negative-' + str(number))
            shutil.copytree(classes, out)
            mutation = work / ('mutant-' + str(number)) / 'AndroidNodeCandidatePreparation.java'
            mutation.parent.mkdir()
            mutation.write_text(original.replace(before, after))
            cp = os.pathsep.join((str(out), str(jar)))
            subprocess.run(['javac', '--release', '17', '-encoding', 'UTF-8', '-proc:none', '-cp', cp, '-d', str(out), str(mutation)], check=True, timeout=60)
            result = subprocess.run(['java', '-cp', cp, 'com.eabusham.routervpn.OrderedRuntimeTest', family], capture_output=True, text=True, timeout=60)
            if result.returncode == 0 or witness not in result.stderr:
                raise AssertionError('Temporary supervisor control missed its defect: ' + family + '\n' + result.stdout + '\n' + result.stderr)
            print('Android temporary candidate supervisor rejected: ' + family + '/' + str(number), flush=True)


if __name__ == '__main__':
    main()
