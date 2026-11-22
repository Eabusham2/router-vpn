#!/usr/bin/env python3
"""Compose the shipping candidate worker, Session, Runtime and VPN service.

This executes actual Java ownership and cleanup. OS/TUN, native complete-path
proof and TCP receipt payloads are explicit existing boundary models. The
separate source/store gate and native fifty-socket gate retain those duties.
"""
from pathlib import Path
import importlib.util
import os
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
JAVA = ROOT/'android/app/src/main/java/com/eabusham/routervpn'


def load(name):
    spec = importlib.util.spec_from_file_location('connected_candidate_'+name, ROOT/'android'/(name+'.py'))
    result = importlib.util.module_from_spec(spec);spec.loader.exec_module(result)
    return result


CATALOG = r'''package com.eabusham.routervpn;
final class AndroidNodeCandidateCatalog implements io.nekohasekai.libbox.RouterNodeChainCandidateCatalog {
 String selectedPrefixID(){throw new IllegalStateException("This fixture owns no selected execution packet stop.");}
 final io.nekohasekai.libbox.RouterNodeChainExecution executionOwner=null;
 final AndroidNodeChainSession session;final AndroidNodeStore.ChainCapture originalSource;final io.nekohasekai.libbox.CommandServer server;final int prefix;final String inventory="original connected typed inventory";
 final String inventorySHA="d".repeat(64);boolean invalidated;
 static final class Row{final String id,name,input="original input";Row(String id){this.id=id;name=id;}}
 final java.util.List<Row> rows=java.util.List.of(new Row("one"),new Row("two"));
 AndroidNodeCandidateCatalog(AndroidNodeChainSession session,int prefix)throws Exception{this.session=session;originalSource=session.source;this.prefix=prefix;server=session.candidateServer();}
 static AndroidNodeCandidateCatalog captureSources(android.content.Context context,AndroidNodeStore.ChainCapture source,int prefix){throw new IllegalStateException("No saved-prefix owner in connected typed fixture");}
 void bind(AndroidNodeChainSession value){throw new IllegalStateException("Connected typed catalog already bound");}
 void requireSourcesCurrent(){originalSource.requireCurrent();}
 void requireSavedSourcesCurrent(){requireSourcesCurrent();}
 public String currentInventorySHA256(){try{session.requireCurrent();if(invalidated||session.candidateServer()!=server)throw new IllegalStateException("foreign server");return inventorySHA;}catch(Exception stale){invalidated=true;return "";}}
 void requireCurrent(){if(!inventorySHA.equals(currentInventorySHA256()))throw new IllegalStateException("Original typed connected catalog retired");}
}'''


CASES = r'''
 static final class CandidateCompletion implements AndroidNodeCandidateMeasurement.Callback {
  final CountDownLatch ready=new CountDownLatch(1),closing=new CountDownLatch(1),done=new CountDownLatch(1);volatile Throwable failure;
  public void changed(List<AndroidNodeCandidateResult> rows,String detail){if(rows.size()==2)ready.countDown();if(detail.startsWith("Cancelling;"))closing.countDown();}
  public void finished(Throwable value){failure=value;done.countDown();}
 }
 static void candidateSuccess()throws Exception{for(int count:new int[]{3,4,8})try(Fixture f=new Fixture(count,"awg2-strong","shadowsocks")){
  f.connected();var session=f.owner();var plan=session.capture.FAMILY_FIELD.plan;var box=plan.server;String launch=Files.readString(session.directory.toPath().resolve(AndroidNodeChainCapture.SESSION_FILE));
  int runs=plan.runs,history=AndroidStartupPolicy.recorded;var restore=f.runtime.captureRestore();var catalog=new AndroidNodeCandidateCatalog(session,count-3);var callback=new CandidateCompletion();
  var operation=AndroidNodeCandidateMeasurement.start(catalog,callback);
  try{
   check(callback.ready.await(10,TimeUnit.SECONDS),"typed connected service did not deliver original candidate completion");var measured=RouterNodeChainFAMILYCandidateMeasurement.latest;
   check(measured!=null&&measured.owner==plan&&measured.server==box&&plan.candidate==measured,"typed candidate bypassed the actual complete service owner");
   check(plan.runs==runs&&plan.factories==1&&history==AndroidStartupPolicy.recorded&&launch.equals(Files.readString(session.directory.toPath().resolve(AndroidNodeChainCapture.SESSION_FILE))),"typed measurement reran proof/Last or changed the complete launch");
   check(f.runtime.isConnected()&&session.healthy()&&AndroidMTUMeasurementGate.held(),"typed connected measurement lost the complete original path or activity lease");
   operation.cancel();check(callback.done.await(10,TimeUnit.SECONDS)&&operation.joined(),"typed connected cancellation did not join");
   check(plan.healthy()&&!box.closed&&plan.candidate==null&&!AndroidMTUMeasurementGate.held(),"typed measurement close stopped the complete original VPN");
   f.stop();check(plan.nativeClosed()&&session.released(),"typed complete source failed normal joined retirement");
   Result restored=new Result();f.runtime.restore(restore,AndroidHomeStateStore.snapshot(f.service),restored);restored.finished();check(restored.ok&&f.runtime.restoredMatches(restore),"typed candidate activity changed complete original restore");
   var replacement=f.owner();check(replacement!=session&&replacement.source==session.source&&replacement.capture.FAMILY_FIELD.plan!=plan&&replacement.capture.FAMILY_FIELD.plan.runs==1,"typed restore reused original native handle or changed source");
   operation.cancel();check(f.owner()==replacement&&replacement.healthy(),"retired typed candidate canceled a replacement connection");f.stop();
  }finally{RouterNodeChainFAMILYCandidateMeasurement.holdClose=false;operation.cancel();callback.done.await(10,TimeUnit.SECONDS);}
 }}
 static void candidateDrain(boolean prepareFailure)throws Exception{try(Fixture f=new Fixture(3,"wg","shadowsocks")){
  f.connected();var session=f.owner();var plan=session.capture.FAMILY_FIELD.plan;var box=plan.server;var callback=new CandidateCompletion();
  RouterNodeChainFAMILYCandidateMeasurement.holdClose=true;RouterNodeChainFAMILYCandidateMeasurement.prepareFailure=prepareFailure;
  var operation=AndroidNodeCandidateMeasurement.start(new AndroidNodeCandidateCatalog(session,0),callback);
  try{
   if(!prepareFailure)check(callback.ready.await(10,TimeUnit.SECONDS),"typed drain fixture did not receive original candidate callback");operation.cancel();
   check(callback.closing.await(10,TimeUnit.SECONDS),"typed candidate pending callback lost its cleanup watcher");
   check(!operation.joined()&&AndroidMTUMeasurementGate.held()&&AndroidNodeCandidateMeasurement.busy(),"typed candidate callback released activity before join");
   check(!f.runtime.stopAndProve()&&!session.released()&&!box.closed&&session.directory.exists(),"typed service closed original Box before candidate callback joined");
   check(plan.candidate!=null,"typed service discarded original candidate retirement slot");
   RouterNodeChainFAMILYCandidateMeasurement.holdClose=false;check(callback.done.await(10,TimeUnit.SECONDS)&&operation.joined(),"typed candidate pending callback did not finish");f.stop();check(session.released()&&plan.nativeClosed(),"typed candidate retirement lost its original complete close receipt");
  }finally{RouterNodeChainFAMILYCandidateMeasurement.prepareFailure=false;RouterNodeChainFAMILYCandidateMeasurement.holdClose=false;operation.cancel();callback.done.await(10,TimeUnit.SECONDS);}
 }}
 static void candidateReservation()throws Exception{try(Fixture f=new Fixture(3,"wg","shadowsocks")){
  f.connected();var session=f.owner();var plan=session.capture.FAMILY_FIELD.plan;var box=plan.server;var catalog=new AndroidNodeCandidateCatalog(session,0);
  var original=Libbox.routerNodeChainFAMILYNewCandidateMeasurement(plan,box,0,catalog.inventory,catalog);check(!original.prepareAttempted,"typed reservation ran a callback before returning the native handle");original.prepare();
  var callback=new CandidateCompletion();var operation=AndroidNodeCandidateMeasurement.start(catalog,callback);
  try{
   check(callback.done.await(10,TimeUnit.SECONDS)&&callback.failure!=null&&operation.joined(),"duplicate typed factory failed to report its refusal");
   check(plan.candidate==original&&!original.closed&&original.closes==0&&session.healthy()&&!box.closed,"duplicate typed factory cleanup closed the preexisting same-key operation");
   original.close();var replacement=Libbox.routerNodeChainFAMILYNewCandidateMeasurement(plan,box,0,catalog.inventory,catalog);replacement.prepare();boolean refused=false;try{original.close();}catch(IllegalStateException stale){refused="foreign candidate cleanup".equals(stale.getMessage());}check(refused,"stale typed handle accepted a same-key replacement cleanup receipt");
   check(plan.candidate==replacement&&!replacement.closed&&session.healthy(),"stale typed cleanup closed the same-key replacement");replacement.close();f.stop();
  }finally{RouterNodeChainFAMILYCandidateMeasurement.holdClose=false;operation.cancel();callback.done.await(10,TimeUnit.SECONDS);if(plan.candidate!=null)plan.candidate.close();}
 }}
 static void candidateSource()throws Exception{try(Fixture f=new Fixture(4,"awg2-fast","shadowsocks")){
  f.connected();var session=f.owner();var plan=session.capture.FAMILY_FIELD.plan;var callback=new CandidateCompletion();var operation=AndroidNodeCandidateMeasurement.start(new AndroidNodeCandidateCatalog(session,1),callback);
  try{check(callback.ready.await(10,TimeUnit.SECONDS),"typed source fixture missed original candidate callback");f.source.valid=false;check(callback.done.await(10,TimeUnit.SECONDS)&&callback.failure!=null,"typed candidate retained a replaced complete source");check(plan.candidate==null&&!AndroidMTUMeasurementGate.held(),"typed stale source abandoned original candidate slot");}
  finally{operation.cancel();callback.done.await(10,TimeUnit.SECONDS);}
 }}
 public static void main(String[] args)throws Exception{
  try{String phase=args.length==0?"all":args[0];if(phase.equals("all")||phase.equals("success"))candidateSuccess();if(phase.equals("all")||phase.equals("drain"))candidateDrain(false);if(phase.equals("all")||phase.equals("prepare"))candidateDrain(true);if(phase.equals("all")||phase.equals("reservation"))candidateReservation();if(phase.equals("all")||phase.equals("source"))candidateSource();System.out.println("Android FAMILY connected candidates: "+checks+" shipping service/session ownership checks PASS; OS/native boundaries modelled");}
  finally{RouterNodeChainFAMILYCandidateMeasurement.holdClose=false;AndroidNodeCandidateMeasurement.cancelActive();}
 }
}'''


def sources(family):
    name = 'socks' if family == 'SOCKS' else 'connect'
    host = load('test_android_node_chain_'+name+'_runtime')
    owner = load('test_android_node_candidate_preparation_owner')
    result = dict(host.SOURCES)
    app, native = host.APP, host.NATIVE
    result[app+'AndroidNodeCandidateCatalog.java'] = CATALOG
    # Use the same explicit receipt shape as the existing integrated owner
    # fixture; retain real source/config identity from this exact native owner.
    raw = owner.SOURCES[native+'RouterNodeChainCandidateMeasurement.java'].replace('RouterNodeChainCandidateMeasurement', 'RouterNodeChain'+family+'CandidateMeasurement')
    ordinary_prepare = ' public void prepare(){}\n'
    if raw.count(ordinary_prepare) != 1:
        raise AssertionError('Original ordinary candidate Prepare fixture changed')
    raw = raw.replace(ordinary_prepare, '')
    before = 'final int prefix;public RouterNodeChain'+family+'CandidateMeasurement(){this(0);}public RouterNodeChain'+family+'CandidateMeasurement(int prefix){this.prefix=prefix;latest=this;}'
    after = '''public static boolean prepareFailure;public boolean prepared,prepareAttempted,closed;final int prefix;public final RouterNodeChainFAMILY owner;public final CommandServer server;public final RouterNodeChainCandidateCatalog catalog;
 public RouterNodeChainFAMILYCandidateMeasurement(RouterNodeChainFAMILY owner,CommandServer server,int prefix,RouterNodeChainCandidateCatalog catalog)throws Exception{if(owner==null||owner.server!=server||!owner.healthy())throw new IllegalStateException("unproved original typed candidate owner");this.owner=owner;this.server=server;this.prefix=prefix;this.catalog=catalog;synchronized(owner){if(owner.candidate!=null)throw new IllegalStateException("original candidate remains owned");owner.candidate=this;latest=this;}}
 public void prepare()throws Exception{synchronized(owner){if(closed||owner.candidate!=this||prepareAttempted)throw new IllegalStateException("foreign or repeated candidate preparation");prepareAttempted=true;if(!owner.healthy()||owner.server!=server||catalog.currentInventorySHA256().isEmpty())throw new IllegalStateException("original typed preparation owner changed");if(prepareFailure)throw new IllegalStateException("late original typed preparation");prepared=true;}}
 private void requirePrepared(){if(closed||owner.candidate!=this||!prepared)throw new IllegalStateException("original candidate handle did not prepare");}'''.replace('FAMILY', family)
    if raw.count(before) != 1:
        raise AssertionError('Integrated original candidate model boundary changed')
    raw = raw.replace(before, after).replace('.put("source_sha256","a".repeat(64)).put("config_sha256","b".repeat(64))', '.put("source_sha256",owner.sourceSHA256()).put("config_sha256",owner.configSHA256())')
    raw = raw.replace('public void close()throws Exception{closes++;if(holdClose)throw new IllegalStateException("original candidate callback still running");}', 'public void close()throws Exception{synchronized(owner){if(owner.candidate!=null&&owner.candidate!=this)throw new IllegalStateException("foreign candidate cleanup");if(closed)return;if(owner.candidate!=this)throw new IllegalStateException("missing original candidate cleanup");closes++;if(holdClose)throw new IllegalStateException("original candidate callback still running");closed=true;owner.candidate=null;}}')
    raw = raw.replace('public String metadata()throws Exception{', 'public String metadata()throws Exception{requirePrepared();').replace('public String statusJSON()throws Exception{', 'public String statusJSON()throws Exception{requirePrepared();').replace('this.request=request;this.id=id;starts++;', 'requirePrepared();this.request=request;this.id=id;starts++;')
    result[native+'RouterNodeChain'+family+'CandidateMeasurement.java'] = raw
    path = native+'RouterNodeChain'+family+'.java'
    raw = result[path]
    raw = raw.replace('public final String input;', 'public volatile RouterNodeChain'+family+'CandidateMeasurement candidate;public final String input;')
    raw = raw.replace('closes++;retired=true;if(failClose', 'closes++;retired=true;if(candidate!=null)candidate.close();if(failClose')
    result[path] = raw
    path = native+'Libbox.java';raw = result[path]
    before = '''public static RouterNodeChainFAMILYCandidateMeasurement routerNodeChainFAMILYNewCandidateMeasurement(RouterNodeChainFAMILY owner,CommandServer server,int prefix,String inventory,Object catalog)throws Exception{throw new IllegalStateException("No typed connected candidate runtime in this ordinary fixture");}'''.replace('FAMILY', family)
    after = '''public static RouterNodeChainFAMILYCandidateMeasurement routerNodeChainFAMILYNewCandidateMeasurement(RouterNodeChainFAMILY owner,CommandServer server,int prefix,String inventory,RouterNodeChainCandidateCatalog catalog)throws Exception{return new RouterNodeChainFAMILYCandidateMeasurement(owner,server,prefix,catalog);}'''.replace('FAMILY', family)
    if raw.count(before) != 1:
        raise AssertionError('Original unavailable typed factory changed')
    raw = raw.replace(before, after)
    if 'routerNodeChain'+family+'CloseCandidateMeasurement' in raw:
        raise AssertionError('Ambiguous typed cleanup fallback remains: '+family)
    # Ordinary branch is intentionally unavailable in this typed host fixture.
    raw = raw[:-1]+'''public static RouterNodeChainCandidateMeasurement routerNodeChainNewCandidateMeasurement(RouterNodeChain plan,CommandServer server,int prefix,String inventory,Object catalog)throws Exception{throw new IllegalStateException("No generic candidate authority in typed fixture");}
public static void routerNodeChainCloseCandidateMeasurement(RouterNodeChain plan,int prefix,String inventory)throws Exception{throw new IllegalStateException("No generic candidate retirement in typed fixture");}}'''
    result[path] = raw
    result[native+'RouterNodeChainCandidateMeasurement.java'] = owner.SOURCES[native+'RouterNodeChainCandidateMeasurement.java']
    result[app+'AndroidNodeCandidatePrefixCapture.java'] = owner.SOURCES[app+'AndroidNodeCandidatePrefixCapture.java']
    result[native+'RouterNodeChainCandidatePreparation.java'] = owner.SOURCES[native+'RouterNodeChainCandidatePreparation.java']
    start = host.HARNESS[:host.HARNESS.index(' static void success()')]
    start = start.replace('Typed'+family+'HostTest', 'TypedConnectedCandidateHostTest')
    result[app+'TypedConnectedCandidateHostTest.java'] = start+CASES.replace('FAMILY_FIELD', name).replace('FAMILY', family)
    return host, result


def main():
    jar = Path(os.environ.get('ANDROID_JSON_JAR', '/usr/share/java/com.android.json.jar'))
    for family in ('SOCKS', 'CONNECT'):
        host, boundary = sources(family)
        with tempfile.TemporaryDirectory(prefix='routervpn-typed-connected-host-') as directory:
            work=Path(directory);src=work/'src';classes=work/'classes'
            for name, text in boundary.items():
                target=src/name;target.parent.mkdir(parents=True, exist_ok=True);target.write_text(text)
            names=('AndroidHomeStateStore', 'AndroidConnectionSelection', 'AndroidNodeChain'+family+'Capture', 'AndroidNodeChainSession', 'AndroidNodeChainMTUPlatform', 'AndroidNodeChainRuntime', 'LayeredVpnService', 'AndroidNodeCandidateMeasurement', 'AndroidNodeCandidateResult', 'AndroidMTUMeasurementGate')
            originals={name:(JAVA/(name+'.java')).read_text() for name in names}
            for name, text in originals.items():
                (src/host.APP/(name+'.java')).write_text(text)
            subprocess.run(['javac', '--release', '17', '-encoding', 'UTF-8', '-proc:none', '-cp', str(jar), '-d', str(classes), *map(str, src.rglob('*.java'))], check=True, timeout=60)
            run=['java', '-cp', os.pathsep.join((str(classes), str(jar))), 'com.eabusham.routervpn.TypedConnectedCandidateHostTest']
            subprocess.run(run, check=True, timeout=120)
            controls=(
                ('LayeredVpnService', 'chain.execution != null || chain.typedNative()', 'chain.execution != null', 'drain', 'typed service closed original Box before candidate callback joined'),
                ('AndroidNodeCandidateMeasurement', 'boolean joined=false;', 'AndroidMTUMeasurementGate.release(lease);boolean joined=false;', 'drain', 'typed candidate callback released activity before join'),
            )
            for index, (name, before, after, phase, witness) in enumerate(controls):
                if originals[name].count(before) != 1:
                    raise AssertionError('Original host control boundary changed: '+name)
                private=work/('control-'+str(index));private.mkdir();target=private/'classes';shutil.copytree(classes, target)
                source=private/(name+'.java');source.write_text(originals[name].replace(before, after));cp=os.pathsep.join((str(target), str(jar)))
                subprocess.run(['javac', '--release', '17', '-encoding', 'UTF-8', '-proc:none', '-cp', cp, '-d', str(target), str(source)], check=True, timeout=60)
                result=subprocess.run(['java', '-cp', cp, 'com.eabusham.routervpn.TypedConnectedCandidateHostTest', phase], text=True, capture_output=True, timeout=120)
                if result.returncode != 1 or 'Exception in thread "main" java.lang.AssertionError: '+witness not in result.stderr:
                    raise AssertionError('Actual service omission missed exact witness: '+family+' '+witness+'\n'+result.stdout+result.stderr)
                print('Android typed connected service causal refusal:', family, witness, flush=True)


if __name__ == '__main__':
    main()
