#!/usr/bin/env python3
"""Actual Android Session/Runtime/measurement with explicit native and store seams.

This does not claim encrypted traffic or generated SDK acceptance. The actual
AAR verifier separately requires the generated execution candidate signature.
The selected source is never reopened as a Local measurement or compared again.
"""
from pathlib import Path
import os
import importlib
import subprocess
import sys
import tempfile
import test_android_node_chain_execution_runtime as host
import test_android_node_candidate_preparation_owner as ordinary

ROOT, JAVA, APP, NATIVE = host.ROOT, host.JAVA, host.APP, host.NATIVE

CATALOG = r'''package com.eabusham.routervpn;
final class AndroidNodeCandidateCatalog implements io.nekohasekai.libbox.RouterNodeChainCandidateCatalog {
 final AndroidNodeChainSession session;final AndroidNodeStore.ChainCapture originalSource;final io.nekohasekai.libbox.CommandServer server;
 final io.nekohasekai.libbox.RouterNodeChainExecution executionOwner;final int prefix;final String inventory="original entry inventory",inventorySHA="d".repeat(64);
 static final class Row{final String id,name,input="original input";Row(String id){this.id=id;name=id;}}
 final java.util.List<Row> rows=java.util.List.of(new Row("one"),new Row("two"));
 AndroidNodeCandidateCatalog(AndroidNodeChainSession session,int prefix)throws Exception{this.session=session;originalSource=session.source;this.prefix=prefix;server=session.candidateServer();executionOwner=session.candidateExecutionOwner();}
 static AndroidNodeCandidateCatalog captureSources(android.content.Context c,AndroidNodeStore.ChainCapture s,int p){throw new IllegalStateException("No saved prefix in selected execution fixture");}
 void bind(AndroidNodeChainSession s){throw new IllegalStateException("Already bound catalog");}
 void requireSourcesCurrent(){originalSource.requireCurrent();}void requireSavedSourcesCurrent(){requireSourcesCurrent();}
 public String currentInventorySHA256(){try{session.requireCurrent();return session.candidateServer()==server&&session.candidateExecutionOwner()==executionOwner?inventorySHA:"";}catch(Exception stale){return "";}}
 void requireCurrent(){if(!inventorySHA.equals(currentInventorySHA256()))throw new IllegalStateException("Original execution catalog retired");}
}'''

CASES = r'''
 static final class Completion implements AndroidNodeCandidateMeasurement.Callback {
  final CountDownLatch ready=new CountDownLatch(1),closing=new CountDownLatch(1),done=new CountDownLatch(1);volatile Throwable failure;
  public void changed(List<AndroidNodeCandidateResult> rows,String detail){if(rows.size()==2)ready.countDown();if(detail.startsWith("Cancelling;"))closing.countDown();}
  public void finished(Throwable error){failure=error;done.countDown();}
 }
 static void success()throws Exception{for(int count:new int[]{2,4,8})for(String variant:List.of("server/server","auto/server","auto/local"))try(Fixture f=new Fixture(count,variant.split("/")[0])){
  String selected=variant.split("/")[1];RouterNodeChainExecution.configured=p->p.selected=selected;f.connected();var session=f.owner();var plan=session.execution.plan;int runs=plan.runs,constructors=RouterNodeChainExecution.ordinaryPreparations;String source=f.source.execution;
  var callback=new Completion();var op=AndroidNodeCandidateMeasurement.start(new AndroidNodeCandidateCatalog(session,0),callback);
  try{check(callback.ready.await(8,TimeUnit.SECONDS),"selected execution never delivered current entry rows");var nativeOwner=RouterNodeChainExecutionCandidateMeasurement.latest;
   check(nativeOwner!=null&&nativeOwner.owner==plan&&nativeOwner.server==session.candidateServer(),"candidate used dormant Local instead of selected original execution");
   check(nativeOwner.prepared&&nativeOwner.starts==2&&plan.runs==runs&&RouterNodeChainExecution.ordinaryPreparations==constructors,"candidate reran Compare or reopened a Local proof");
   check(source.equals(f.source.execution)&&selected.equals(session.provedExecution())&&session.healthy(),"candidate changed requested or selected execution");
   check(AndroidMTUMeasurementGate.held(),"selected candidate released MTU before native close");
   op.cancel();check(callback.done.await(8,TimeUnit.SECONDS)&&op.joined()&&callback.failure==null,"selected candidate did not join");
   check(plan.candidate==null&&session.healthy()&&!plan.server.closed&&!AndroidMTUMeasurementGate.held(),"candidate closed complete selected VPN or leaked activity");f.stop();
  }finally{op.cancel();callback.done.await(8,TimeUnit.SECONDS);}
 }}
 static void faults()throws Exception{for(String fault:List.of("preparation-source","preparation-config","requested","selected","projection","epoch"))try(Fixture f=new Fixture(4,"auto")){
  f.connected();RouterNodeChainExecutionCandidateMeasurement.fault=fault;var callback=new Completion();var op=AndroidNodeCandidateMeasurement.start(new AndroidNodeCandidateCatalog(f.owner(),0),callback);
  try{check(callback.done.await(8,TimeUnit.SECONDS)&&callback.failure!=null,"foreign "+fault+" metadata accepted");check(!AndroidMTUMeasurementGate.held()&&f.owner().healthy(),"metadata refusal lost original cleanup");}
  finally{RouterNodeChainExecutionCandidateMeasurement.fault="";op.cancel();callback.done.await(8,TimeUnit.SECONDS);}
 }
 try(Fixture f=new Fixture(4,"auto")){f.connected();var callback=new Completion();var op=AndroidNodeCandidateMeasurement.start(new AndroidNodeCandidateCatalog(f.owner(),1),callback);check(callback.done.await(8,TimeUnit.SECONDS)&&callback.failure!=null,"selected later prefix admitted");}
 }
 static void changed()throws Exception{for(String fault:List.of("epoch","source","owner"))try(Fixture f=new Fixture(4,"auto")){
  f.connected();var session=f.owner();var plan=session.execution.plan;var callback=new Completion();var op=AndroidNodeCandidateMeasurement.start(new AndroidNodeCandidateCatalog(session,0),callback);
  try{check(callback.ready.await(8,TimeUnit.SECONDS),"changed fixture lacked original rows");if(fault.equals("epoch"))plan.epoch++;else if(fault.equals("source"))f.source.valid=false;else plan.valid=false;
   check(callback.done.await(8,TimeUnit.SECONDS)&&callback.failure!=null,"changed execution observation retained candidate scores");check(plan.candidate==null&&!AndroidMTUMeasurementGate.held(),"changed execution abandoned exact cleanup");}
  finally{f.source.valid=true;plan.valid=true;op.cancel();callback.done.await(8,TimeUnit.SECONDS);}
 }}
 static void held()throws Exception{for(boolean prepareFailure:new boolean[]{false,true})try(Fixture f=new Fixture(4,"auto")){
  f.connected();var session=f.owner();var plan=session.execution.plan;var callback=new Completion();RouterNodeChainExecutionCandidateMeasurement.holdClose=true;RouterNodeChainExecutionCandidateMeasurement.prepareFailure=prepareFailure;
  var op=AndroidNodeCandidateMeasurement.start(new AndroidNodeCandidateCatalog(session,0),callback);
  try{if(!prepareFailure)check(callback.ready.await(8,TimeUnit.SECONDS),"held fixture lacked original rows");op.cancel();check(callback.closing.await(8,TimeUnit.SECONDS),"held original cleanup was not observed");
   check(!op.joined()&&AndroidMTUMeasurementGate.held()&&AndroidNodeCandidateMeasurement.busy()&&plan.candidate!=null,"selected cleanup released MTU before exact Close joined");
   check(!f.runtime.stopAndProve()&&!session.released()&&!plan.server.closed,"selected service discarded unjoined candidate callbacks");
   RouterNodeChainExecutionCandidateMeasurement.holdClose=false;check(callback.done.await(8,TimeUnit.SECONDS)&&op.joined(),"selected original cleanup never joined");f.stop();}
  finally{RouterNodeChainExecutionCandidateMeasurement.prepareFailure=false;RouterNodeChainExecutionCandidateMeasurement.holdClose=false;op.cancel();callback.done.await(8,TimeUnit.SECONDS);}
 }}
 static void reservation()throws Exception{try(Fixture f=new Fixture(4,"auto")){
  f.connected();var session=f.owner();var plan=session.execution.plan;var catalog=new AndroidNodeCandidateCatalog(session,0);
  var first=Libbox.routerNodeChainExecutionNewCandidateMeasurement(plan,catalog.server,0,catalog.inventory,catalog);check(!first.prepared,"factory ran catalog before returning reservation");first.prepare();
  var callback=new Completion();var op=AndroidNodeCandidateMeasurement.start(catalog,callback);check(callback.done.await(8,TimeUnit.SECONDS)&&callback.failure!=null,"duplicate reservation admitted");
  check(plan.candidate==first&&!first.closed&&first.closes==0,"duplicate factory closed preexisting operation");first.close();var replacement=Libbox.routerNodeChainExecutionNewCandidateMeasurement(plan,catalog.server,0,catalog.inventory,catalog);replacement.prepare();reject(first::close,"stale same-key close accepted replacement");check(plan.candidate==replacement&&!replacement.closed,"stale close retired replacement");replacement.close();f.stop();
 }}
 public static void main(String[] args)throws Exception{try{String phase=args.length==0?"all":args[0];if(phase.equals("all")||phase.equals("success"))success();if(phase.equals("all")||phase.equals("faults"))faults();if(phase.equals("all")||phase.equals("changed"))changed();if(phase.equals("all")||phase.equals("held"))held();if(phase.equals("all")||phase.equals("reservation"))reservation();System.out.println("Android selected execution entry: "+checks+" actual host checks PASS; native and store seams modelled");}finally{AndroidNodeCandidateMeasurement.cancelActive();}}
}'''


def sources(family='ordinary'):
    boundary=host if family=='ordinary' else importlib.import_module('test_android_'+family+'_execution_runtime')
    result = boundary.sources()
    result[APP+'AndroidNodeCandidateCatalog.java'] = CATALOG
    result[APP+'AndroidNodeCandidatePrefixCapture.java'] = ordinary.SOURCES[APP+'AndroidNodeCandidatePrefixCapture.java']
    result[NATIVE+'RouterNodeChainCandidatePreparation.java'] = ordinary.SOURCES[NATIVE+'RouterNodeChainCandidatePreparation.java']
    result[NATIVE+'RouterNodeChainCandidateMeasurement.java'] = ordinary.SOURCES[NATIVE+'RouterNodeChainCandidateMeasurement.java']
    raw = ordinary.SOURCES[NATIVE+'RouterNodeChainCandidateMeasurement.java'].replace('RouterNodeChainCandidateMeasurement','RouterNodeChainExecutionCandidateMeasurement')
    raw=raw.replace(' public void prepare(){}\n','')
    before='final int prefix;public RouterNodeChainExecutionCandidateMeasurement(){this(0);}public RouterNodeChainExecutionCandidateMeasurement(int prefix){this.prefix=prefix;latest=this;}'
    after='''public static String fault="";public static boolean prepareFailure;public boolean prepared,attempted,closed;public final RouterNodeChainExecution owner;public final CommandServer server;final RouterNodeChainCandidateCatalog catalog;final int prefix;
 public RouterNodeChainExecutionCandidateMeasurement(RouterNodeChainExecution owner,CommandServer server,int prefix,RouterNodeChainCandidateCatalog catalog)throws Exception{if(prefix!=0||!owner.healthy()||owner.server!=server)throw new IllegalStateException("foreign selected entry");this.owner=owner;this.server=server;this.catalog=catalog;this.prefix=prefix;synchronized(owner){if(owner.candidate!=null)throw new IllegalStateException("original candidate still reserved");owner.candidate=this;latest=this;}}
 public void prepare()throws Exception{synchronized(owner){if(owner.candidate!=this||closed||attempted)throw new IllegalStateException("foreign preparation");attempted=true;if(prepareFailure||catalog.currentInventorySHA256().isEmpty())throw new IllegalStateException("original preparation failed");prepared=true;}}
 private void current(){if(owner.candidate!=this||closed||!prepared)throw new IllegalStateException("original candidate retired");}'''
    assert raw.count(before)==1
    raw=raw.replace(before,after)
    raw=raw.replace('public String metadata()throws Exception{return new JSONObject()', 'public String metadata()throws Exception{current();return new JSONObject().put("preparation_source_sha256",fault.equals("preparation-source")?"0".repeat(64):owner.sourceSHA256()).put("preparation_config_sha256",fault.equals("preparation-config")?"0".repeat(64):owner.configSHA256()).put("requested_execution",fault.equals("requested")?"local":owner.requestedExecution()).put("execution",fault.equals("selected")?"wrong":owner.execution()).put("selection_epoch",fault.equals("epoch")?0:owner.epoch)')
    raw=raw.replace('.put("source_sha256","a".repeat(64))','.put("source_sha256",fault.equals("projection")?"invalid":"a".repeat(64))')
    raw=raw.replace('public void close()throws Exception{closes++;if(holdClose)throw new IllegalStateException("original candidate callback still running");}', 'public void close()throws Exception{synchronized(owner){if(owner.candidate!=null&&owner.candidate!=this)throw new IllegalStateException("foreign candidate cleanup");if(closed)return;if(owner.candidate!=this)throw new IllegalStateException("missing original slot");closes++;if(holdClose)throw new IllegalStateException("original candidate callback still running");closed=true;owner.candidate=null;}}')
    raw=raw.replace('this.request=request;this.id=id;starts++;','current();this.request=request;this.id=id;starts++;')
    result[NATIVE+'RouterNodeChainExecutionCandidateMeasurement.java']=raw
    raw=result[NATIVE+'RouterNodeChainExecution.java'].replace(' public CommandServer server;', ' public volatile RouterNodeChainExecutionCandidateMeasurement candidate;public long epoch=1;\n public CommandServer server;').replace('  closes++;cancelled=true;', '  if(candidate!=null)candidate.close();closes++;cancelled=true;')
    result[NATIVE+'RouterNodeChainExecution.java']=raw
    raw=result[NATIVE+'Libbox.java']
    old='public static RouterNodeChainExecutionCandidateMeasurement routerNodeChainExecutionNewCandidateMeasurement(RouterNodeChainExecution owner,CommandServer server,int prefix,String inventory,Object catalog)throws Exception{throw new IllegalStateException("No typed connected candidate runtime in this ordinary fixture");}'
    assert raw.count(old)==1
    raw=raw.replace(old,'public static RouterNodeChainExecutionCandidateMeasurement routerNodeChainExecutionNewCandidateMeasurement(RouterNodeChainExecution owner,CommandServer server,int prefix,String inventory,RouterNodeChainCandidateCatalog catalog)throws Exception{return new RouterNodeChainExecutionCandidateMeasurement(owner,server,prefix,catalog);}')
    raw=raw[:-1]+'''public static RouterNodeChainCandidateMeasurement routerNodeChainNewCandidateMeasurement(RouterNodeChain plan,CommandServer server,int prefix,String inventory,Object catalog)throws Exception{throw new IllegalStateException("Dormant Local candidate refused");}}'''
    result[NATIVE+'Libbox.java']=raw
    harness=host.HARNESS if family=='ordinary' else boundary.runtime_harness()
    cases=CASES if family=='ordinary' else CASES.replace('new int[]{2,4,8}','new int[]{3,4,8}')
    if family=='ordinary':
        cases=cases.replace('for(int count:new int[]{2,4,8})for(String variant:', 'for(boolean imported:new boolean[]{false,true})for(int count:imported?new int[]{3,4,8}:new int[]{2,4,8})for(String variant:').replace('new Fixture(count,variant.split("/")[0])','new Fixture(count,variant.split("/")[0],imported)')
    result[APP+'ExecutionEntryCandidateTest.java']=harness[:harness.index(' static void success()')].replace('OrderedExecutionRuntimeTest','ExecutionEntryCandidateTest')+cases
    return result



def verify_abi():
    source=(ROOT/'android/build-sing-box-libbox.sh').read_text()
    start=source.index('require_execution_entry_candidate_api() {')
    body=source[start:source.index('\n}\n',start)+3]
    call='  require_execution_entry_candidate_api "$api_list" "$tmp/router-node-chain-execution-candidate.javap" || return 1'
    assert source.count(call)==1
    assert source[:source.index(call)].count('javap -classpath "$classes" io.nekohasekai.libbox.RouterNodeChainExecutionCandidateMeasurement >"$tmp/router-node-chain-execution-candidate.javap"')==1
    factory='io.nekohasekai.libbox.RouterNodeChainExecutionCandidateMeasurement routerNodeChainExecutionNewCandidateMeasurement(io.nekohasekai.libbox.RouterNodeChainExecution, io.nekohasekai.libbox.CommandServer, int, java.lang.String, io.nekohasekai.libbox.RouterNodeChainCandidateCatalog) throws java.lang.Exception;'
    methods=['void prepare() throws java.lang.Exception;', 'java.lang.String metadata();', 'java.lang.String captureSHA256();', 'void start(java.lang.String, java.lang.String) throws java.lang.Exception;', 'void cancel(java.lang.String);', 'void drain(java.lang.String) throws java.lang.Exception;', 'java.lang.String statusJSON();', 'void networkChanged();', 'void close() throws java.lang.Exception;']
    cases=[('complete',factory,methods,True),('wrong-owner',factory.replace('RouterNodeChainExecution,','RouterNodeChain,'),methods,False),('fallback',factory+'\nvoid routerNodeChainExecutionCloseCandidateMeasurement();',methods,False)]
    cases += [('missing-'+str(i),factory,methods[:i]+methods[i+1:],False) for i in range(len(methods))]
    with tempfile.TemporaryDirectory(prefix='entry-candidate-abi-') as directory:
        api,owner=Path(directory)/'api',Path(directory)/'owner'
        for name,f,m,accepted in cases:
            api.write_text(f+'\n');owner.write_text('\n'.join(m)+'\n')
            result=subprocess.run(['bash','-c',body+'\nrequire_execution_entry_candidate_api "$1" "$2"','entry-abi',str(api),str(owner)],text=True,capture_output=True,timeout=10)
            assert (result.returncode==0)==accepted,(name,result.stdout,result.stderr)
    print('Selected entry generated-ABI guard: '+str(len(cases))+' explicit signature boundaries PASS; no generated artifact claimed',flush=True)


def execute(family):
    jar=Path(os.environ.get('ANDROID_JSON_JAR','/usr/share/java/com.android.json.jar'))
    with tempfile.TemporaryDirectory(prefix='routervpn-execution-entry-host-') as directory:
        src=Path(directory)/'src';classes=Path(directory)/'classes'
        for path,text in sources(family).items():
            target=src/path;target.parent.mkdir(parents=True,exist_ok=True);target.write_text(text)
        names=('AndroidHomeStateStore','AndroidConnectionSelection','AndroidNodeChainExecutionCapture','AndroidNodeChainSession','AndroidNodeChainMTUPlatform','AndroidNodeChainRuntime','LayeredVpnService','AndroidNodeCandidateMeasurement','AndroidNodeCandidateResult','AndroidMTUMeasurementGate')
        if family in ('socks','connect'):names += ('AndroidNodeChain'+('SOCKS' if family=='socks' else 'CONNECT')+'Capture',)
        originals={name:(JAVA/(name+'.java')).read_text() for name in names}
        for name,text in originals.items():(src/APP/(name+'.java')).write_text(text)
        def compile():subprocess.run(['javac','--release','17','-encoding','UTF-8','-proc:none','-cp',str(jar),'-d',str(classes),*map(str,src.rglob('*.java'))],check=True,timeout=60)
        run=['java','-cp',os.pathsep.join((str(classes),str(jar))),'com.eabusham.routervpn.ExecutionEntryCandidateTest']
        compile();subprocess.run(run,check=True,timeout=120)
        if family!='ordinary':return
        controls=(
            ('if(catalog.executionOwner!=null){','if(false){','success','selected execution never delivered current entry rows'),
            ('||!owner.configSHA256().equals(metadata.getString("preparation_config_sha256"))','', 'faults','foreign preparation-config metadata accepted'),
            ('if(value!=null){if(!request.isEmpty())value.cancel(request);value.close();}','if(value!=null){if(!request.isEmpty())value.cancel(request);if(!borrowedLease)AndroidMTUMeasurementGate.release(lease);value.close();}','held','selected cleanup released MTU before exact Close joined'),
        )
        original=originals['AndroidNodeCandidateMeasurement'];target=src/APP/'AndroidNodeCandidateMeasurement.java'
        for old,new,phase,witness in controls:
            # Factory guard occurs once in capture, metadata check is intentionally separate.
            assert original.count(old)==(2 if old=='if(catalog.executionOwner!=null){' else 1),old
            target.write_text(original.replace(old,new,1));compile()
            result=subprocess.run(run+[phase],text=True,capture_output=True,timeout=120)
            if result.returncode==0 or witness not in result.stdout+result.stderr:raise AssertionError('Compiled entry omission missed '+phase+'\n'+result.stdout+result.stderr)
            target.write_text(original)
            print('Compiled selected entry omission refused: '+phase,flush=True)

def main():
    verify_abi()
    for family in ('ordinary','socks','connect','openvpn'):execute(family)


if __name__=='__main__':
    if sys.argv[1:]==['--bounded-child']:main()
    elif sys.argv[1:]==['--abi-only']:verify_abi()
    elif sys.argv[1:]:raise SystemExit('unknown arguments')
    else:subprocess.run([sys.executable,__file__,'--bounded-child'],check=True,timeout=300)
