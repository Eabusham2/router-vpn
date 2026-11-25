#!/usr/bin/env python3
"""Run the shipping disconnected selected-draft lifecycle and causal controls.

Runtime, Session, preparation, candidate rows and MTU hold run unchanged. Store
purpose guards are extracted from shipping source. Pure compiler, native packet
handles, catalog and Android SDK are explicit doubles; separate Go-backed source
and native fifty gates prove those boundaries. No physical device claim is made.
"""
from pathlib import Path
import os
import subprocess
import sys
import tempfile

import test_android_execution_entry_candidates as entry
import test_android_node_candidate_preparation_owner as ordinary

ROOT, JAVA, APP, NATIVE = entry.ROOT, entry.JAVA, entry.APP, entry.NATIVE

CASES = r'''
 static final class Completion implements AndroidNodeCandidatePreparation.Callback {
  final CountDownLatch done=new CountDownLatch(1);volatile List<AndroidNodeCandidatePreparation.Choice> choices;volatile Throwable failure;
  public void progress(String message){}public void finished(List<AndroidNodeCandidatePreparation.Choice> value,Throwable error){choices=value;failure=error;done.countDown();}
  void finished()throws Exception{check(done.await(10,TimeUnit.SECONDS),"selected draft cleanup did not finish");}
 }
 static boolean retained(){return AndroidNodeCandidatePreparation.retained()!=null;}
 static AndroidNodeCandidatePreparation reserve(Fixture f,int prefix,Completion result)throws Exception {
  f.source.draftPrefix=prefix;AndroidNodeCandidateCatalog.sourcesValid=true;
  RouterNodeChainExecutionCandidateMeasurement.latest=null;RouterNodeChainExecutionCandidateMeasurement.holdClose=false;
  RouterNodeChainExecutionCandidateMeasurement.prepareFailure=false;RouterNodeChainExecutionCandidateMeasurement.fault="";
  RouterNodeChainExecutionCandidateMeasurement.afterPrepare=null;
  return AndroidNodeCandidatePreparation.reserve(f.service,f.runtime,f.source,AndroidHomeStateStore.snapshot(f.service),AndroidNodeChainSession.selection(f.service,f.source),prefix,result);
 }
 static void retire(AndroidNodeCandidatePreparation operation)throws Exception {
  operation.cancelFromUser();await(()->!retained(),"selected draft observer did not retire");
 }
 static void success()throws Exception{
  for(int count:COUNTS)for(String variant:List.of("server/server","auto/server","auto/local"))try(Fixture f=new Fixture(count,variant.split("/")[0])){
   String winner=variant.split("/")[1];int prefix=PREFIX;int created=CommandServer.created,prepared=AndroidStartupPolicy.prepared,recorded=AndroidStartupPolicy.recorded;
   var idle=AndroidHomeStateStore.snapshot(f.service);var settings=new HashMap<>(f.service.getSharedPreferences("router-vpn-unified",0).getAll());
   RouterNodeChainExecution.configured=plan->plan.selected=winner;Completion result=new Completion();var operation=reserve(f,prefix,result);
   try{
    check(CommandServer.created==created&&!operation.prefixOnly(),"selected draft started before permission or borrowed closed Local prefix");
    check(operation.testsSavedPosition(count-1)&&!f.runtime.isConnected(),"selected draft lost its complete final suffix or became an ordinary connection");
    Object purpose=get(f.source,"selectedCandidatePurpose");reject(()->f.source.requireSelectedCandidatePurpose(new Object()),"foreign temporary owner was accepted");
    reject(()->f.source.requireSelectedCandidatePurpose(purpose),"unstarted selected draft acquired native authority");
    RouterNodeChainExecutionCandidateMeasurement.afterPrepare=()->{
     check(!f.runtime.isConnected(),"temporary selected draft escaped through ordinary Connected");
     try{reject(()->f.runtime.captureRestore(),"temporary selected draft supplied ordinary restore authority");}catch(Exception failed){throw new AssertionError(failed);}
     check(AndroidStartupPolicy.prepared==prepared&&AndroidStartupPolicy.recorded==recorded,"temporary selected draft wrote Last history");
    };
    operation.start();result.finished();
    check(result.failure==null&&result.choices!=null&&result.choices.size()==2,"selected draft did not finish its original temporary graph: "+result.failure);
    var candidate=RouterNodeChainExecutionCandidateMeasurement.latest;var plan=candidate.owner;
    check(candidate.prefixPosition()==prefix&&candidate.starts==2&&candidate.closed&&plan.runs==1&&plan.closed&&plan.server.closed,"selected draft reran Compare or delivered before both native owners joined");
    check(plan.requested.equals(variant.split("/")[0])&&plan.selected.equals(winner)&&f.source.execution.equals(plan.requested),"selected draft lost requested execution or original winner");
    check(AndroidStartupPolicy.prepared==prepared&&AndroidStartupPolicy.recorded==recorded&&settings.equals(f.service.getSharedPreferences("router-vpn-unified",0).getAll()),"candidate draft changed persistent connection settings or Last");
    var down=AndroidHomeStateStore.snapshot(f.service);
    check(!down.connected&&down.sessionId.isEmpty()&&down.phase.equals("off")&&down.pathGeneration==idle.pathGeneration+2&&!f.runtime.isActiveOrTransitioning()&&!AndroidMTUMeasurementGate.held(),"selected draft results preceded exact Home DOWN or MTU release");
    check(!AndroidExternalComparisonNetwork.latest.closed,"completed selected draft lost its physical result observer");
    for(var choice:result.choices){check(choice.profile==null&&!choice.saveReason.isEmpty(),"unsaved draft manufactured an unrelated saved-profile proposal");operation.requireSavedResultCurrent(choice.result);}
    reject(()->f.source.requireSelectedCandidatePurpose(purpose),"retired selected draft owner was accepted");
    reject(()->f.source.bindSelectedCandidatePurpose(new Object(),()->true),"retired selected draft was rebound to another temporary owner");
    check(f.owner()==null,"selected draft retained a released private graph");
    try(var files=Files.list(f.files.resolve("layered-sessions"))){check(files.findAny().isEmpty(),"selected draft left its original private workspace");}
   }finally{RouterNodeChainExecutionCandidateMeasurement.afterPrepare=null;retire(operation);}
   check(AndroidExternalComparisonNetwork.latest.closed,"selected draft observer did not join after closing choices");
  }
 }
 static void scope()throws Exception{
  try(Fixture f=new Fixture(SCOPE_COUNT,"auto")){
   f.source.draftPrefix=0;int created=CommandServer.created,history=AndroidStartupPolicy.prepared;
   reject(()->f.source.requirePurpose(-1),"selected draft was admitted as a normal full source");
   reject(()->f.source.requirePurpose(0),"selected draft borrowed a Local packet prefix");
   reject(()->f.source.historyReadback(),"selected draft acquired historical readback");
   Result connected=f.start();connected.finished();check(!connected.ok&&CommandServer.created==created&&AndroidStartupPolicy.prepared==history,"normal Connect admitted a selected draft");
   Completion result=new Completion();var operation=reserve(f,0,result);Object purpose=get(f.source,"selectedCandidatePurpose");
   try{operation.cancelFromUser();result.finished();check(result.choices.isEmpty()&&CommandServer.created==created,"denied draft permission started native traffic");
    reject(()->f.source.requireSelectedCandidatePurpose(purpose),"retired selected draft owner was accepted");}
   finally{retire(operation);}
  }
 }
 static void changed()throws Exception{
  for(String change:List.of("source","settings","network","catalog"))try(Fixture f=new Fixture(SCOPE_COUNT,"auto")){
   RouterNodeChainExecution.configured=plan->plan.selected="server";Completion result=new Completion();var operation=reserve(f,0,result);
   try{
    if(change.equals("source"))f.source.valid=false;
    else if(change.equals("settings"))f.service.getSharedPreferences("router-vpn-unified",0).edit().putString("mtu_policy","changed").commit();
    else if(change.equals("network"))AndroidExternalComparisonNetwork.latest.valid=false;
    else AndroidNodeCandidateCatalog.sourcesValid=false;
    operation.start();result.finished();check(result.failure!=null&&result.choices.isEmpty(),"changed selected draft produced usable scores: "+change);
    check(!f.runtime.isActiveOrTransitioning()&&!AndroidMTUMeasurementGate.held(),"changed selected draft abandoned original cleanup");
   }finally{f.source.valid=true;AndroidNodeCandidateCatalog.sourcesValid=true;retire(operation);}
  }
 }
 static void held()throws Exception{
  try(Fixture f=new Fixture(SCOPE_COUNT,"auto")){
   RouterNodeChainExecution.configured=plan->{plan.selected="server";plan.failCloses=100000;};Completion result=new Completion();var operation=reserve(f,0,result);
   RouterNodeChainExecutionCandidateMeasurement.holdClose=true;
   try{
    operation.start();await(()->RouterNodeChainExecutionCandidateMeasurement.latest!=null&&RouterNodeChainExecutionCandidateMeasurement.latest.starts==2,"held selected draft did not measure");
    var candidate=RouterNodeChainExecutionCandidateMeasurement.latest;var plan=candidate.owner;
    await(()->candidate.closes>0,"selected draft never attempted candidate retirement");
    check(result.done.getCount()==1&&AndroidMTUMeasurementGate.held()&&f.runtime.isActiveOrTransitioning()&&!candidate.closed&&!plan.server.closed,"selected draft released its owner or MTU before original cleanup joined: candidate");
    RouterNodeChainExecutionCandidateMeasurement.holdClose=false;await(()->plan.closes>0,"selected graph retirement never entered");
    check(result.done.getCount()==1&&AndroidMTUMeasurementGate.held()&&f.runtime.isActiveOrTransitioning()&&candidate.closed&&!plan.server.closed,"selected draft released its owner or MTU before original cleanup joined: graph");
    plan.failCloses=0;check(f.runtime.stopAndProve(),"selected draft retry did not join its original graph");result.finished();check(!AndroidMTUMeasurementGate.held()&&!f.runtime.isActiveOrTransitioning()&&plan.closed&&plan.server.closed,"selected draft did not join retained native cleanup");
   }finally{RouterNodeChainExecutionCandidateMeasurement.holdClose=false;RouterNodeChainExecution.latest.failCloses=0;f.runtime.stopAndProve();retire(operation);}
  }
 }
 static void selectedResponseWinners(){
  for(String requested:new String[]{null,"","local","server","auto","unknown"})
   for(String selected:new String[]{null,"","local","server","auto","unknown"}){
    boolean expected="server/server".equals(requested+"/"+selected)||"auto/server".equals(requested+"/"+selected)||"auto/local".equals(requested+"/"+selected);
    check(AndroidNodeChainCapture.selectedResponseWinner(requested,selected)==expected,"wrong selected response owner "+requested+"/"+selected);
   }
 }
 public static void main(String[]args)throws Exception{
  try{String phase=args.length==0?"all":args[0];if(phase.equals("all")||phase.equals("winner"))selectedResponseWinners();if(phase.equals("all")||phase.equals("success"))success();if(phase.equals("all")||phase.equals("scope"))scope();if(phase.equals("all")||phase.equals("changed"))changed();if(phase.equals("all")||phase.equals("held"))held();
   System.out.println("Android selected draft FAMILY: "+checks+" shipping lifecycle checks PASS; native, source compiler and OS seams doubled");
  }finally{AndroidNodeCandidatePreparation.cancelActive();AndroidNodeCandidateMeasurement.cancelActive();}
 }
}
'''


def sources(family):
    result = entry.sources(family)
    old = result.pop(APP + 'ExecutionEntryCandidateTest.java')
    prefix = old[:old.index(' static final class Completion')].replace('ExecutionEntryCandidateTest', 'SelectedDraftCandidateTest')
    counts = 'new int[]{2,4,8}' if family == 'ordinary' else 'new int[]{5,8}' if family == 'multiple' else 'new int[]{3,4,8}'
    position = '0' if family in ('socks', 'connect') else 'count-3' if family in ('openvpn', 'multiple') else 'count-2'
    cases = CASES.replace('COUNTS', counts).replace('PREFIX', position).replace('SCOPE_COUNT', '5' if family == 'multiple' else '4').replace('FAMILY', family)
    result[APP + 'SelectedDraftCandidateTest.java'] = prefix + cases
    result[APP + 'AndroidExternalComparisonNetwork.java'] = ordinary.SOURCES[APP + 'AndroidExternalComparisonNetwork.java']
    # Saving is an explicit unentered boundary: selected drafts return measured
    # choices to their original editor; no saved profile is created by this test.
    result[APP + 'AndroidNodeCandidateProfile.java'] = '''package com.eabusham.routervpn;
final class AndroidNodeCandidateProfile {
 static final class ProposalUnavailable extends Exception{ProposalUnavailable(String reason){super(reason);}}
 interface SavedResultAuthority{void requireCurrent(AndroidNodeCandidateResult result)throws Exception;}
 static AndroidNodeCandidateProfile captureDraftInsertion(AndroidNodeCandidateMeasurement owner,AndroidNodeCandidateResult result,SavedResultAuthority authority,AndroidNodeCandidateProfile named)throws Exception{return null;}
 static AndroidNodeCandidateProfile captureTemporary(AndroidNodeCandidateMeasurement owner,AndroidNodeCandidateResult result,SavedResultAuthority authority)throws Exception{
  owner.requireResult(result);throw new ProposalUnavailable("Save the edited draft separately.");
 }
}'''
    capture = result[APP + 'AndroidNodeChainCapture.java']
    result[APP + 'AndroidNodeChainCapture.java'] = capture.rstrip()[:-1] + '''
 static AndroidNodeChainCapture compile(AndroidNodeStore.ChainCapture source,int prefix){throw new IllegalStateException("Selected draft fixture cannot borrow Local prefix compilation.");}
}'''
    catalog = result[APP + 'AndroidNodeCandidateCatalog.java']
    catalog = catalog.replace(' final AndroidNodeChainSession session;', ' static volatile boolean sourcesValid=true;\n final AndroidNodeChainSession session;')
    catalog = catalog.replace(' static AndroidNodeCandidateCatalog captureSources(', ' AndroidNodeCandidateCatalog(android.content.Context context,AndroidNodeChainSession session,int prefix)throws Exception{this(session,prefix);}\n static AndroidNodeCandidateCatalog captureSources(')
    catalog = catalog.replace('void requireSourcesCurrent(){originalSource.requireCurrent();}', 'void requireSourcesCurrent(){originalSource.requireCurrent();if(!sourcesValid)throw new IllegalStateException("Original catalog changed");}')
    result[APP + 'AndroidNodeCandidateCatalog.java'] = catalog
    mtu = result[APP + 'AndroidMTUSession.java']
    marker = 'throw new IllegalStateException("No ordered candidate MTU proof in this boundary");'
    assert mtu.count(marker) == 1
    result[APP + 'AndroidMTUSession.java'] = mtu.replace(marker, 'if(!AndroidMTUMeasurementGate.owns(lease))throw new IllegalStateException("foreign selected draft MTU owner");activateNodeChain(source);if(failure!=null)throw failure;')
    native = result[NATIVE + 'RouterNodeChainExecutionCandidateMeasurement.java']
    native = native.replace('public static String fault="";', 'public static Runnable afterPrepare;public static String fault="";').replace('prepared=true;}}', 'prepared=true;if(afterPrepare!=null)afterPrepare.run();}}')
    result[NATIVE + 'RouterNodeChainExecutionCandidateMeasurement.java'] = native
    names = ('AndroidHomeStateStore', 'AndroidConnectionSelection', 'AndroidNodeChainExecutionCapture',
             'AndroidNodeChainSession', 'AndroidNodeChainMTUPlatform', 'AndroidNodeChainRuntime',
             'LayeredVpnService', 'AndroidNodeCandidateMetadata','AndroidNodeCandidateMeasurement', 'AndroidNodeCandidateResult',
             'AndroidMTUMeasurementGate', 'AndroidNodeCandidatePreparation')
    if family in ('socks', 'connect'):
        names += ('AndroidNodeChain' + ('SOCKS' if family == 'socks' else 'CONNECT') + 'Capture',)
    for name in names:
        result[APP + name + '.java'] = (JAVA / (name + '.java')).read_text()
    return result


def execute(family):
    jar = Path(os.environ.get('ANDROID_JSON_JAR', '/usr/share/java/com.android.json.jar'))
    with tempfile.TemporaryDirectory(prefix='routervpn-selected-draft-') as directory:
        work = Path(directory); src = work / 'src'; classes = work / 'classes'
        original = sources(family)
        for path, text in original.items():
            target = src / path; target.parent.mkdir(parents=True, exist_ok=True); target.write_text(text)
        def compile():
            subprocess.run(['javac', '--release', '17', '-encoding', 'UTF-8', '-proc:none', '-cp', str(jar), '-d', str(classes), *map(str, src.rglob('*.java'))], check=True, timeout=60)
        run = ['java', '-cp', os.pathsep.join((str(classes), str(jar))), 'com.eabusham.routervpn.SelectedDraftCandidateTest']
        compile(); subprocess.run(run, check=True, timeout=120)
        if family != 'ordinary':
            return
        controls = (
            ('AndroidNodeChainCapture', '"server".equals(requested) || "auto".equals(requested)', '"server".equals(requested)', 'winner', 'wrong selected response owner auto/server'),
            ('AndroidNodeChainCapture', '"local".equals(winner) && "auto".equals(requested)', '"local".equals(winner)', 'winner', 'wrong selected response owner null/local'),
            ('AndroidNodeChainRuntime', 'selectedDraft?this:null', 'null', 'success', 'selected draft did not finish its original temporary graph'),
            ('AndroidNodeStore', 'selectedCandidateDraft()||measurementOnly()&&prefix!=draftPrefix', 'measurementOnly()&&!selectedCandidateDraft()&&prefix!=draftPrefix', 'scope', 'selected draft was admitted as a normal full source'),
            ('AndroidNodeChainRuntime', 'return selectedDraft&&temporary==this&&operation==selectedOperation&&started&&!cancelled&&!closed;', 'return selectedDraft;', 'scope', 'retired selected draft owner was accepted'),
            ('AndroidNodeCandidatePreparation', 'boolean joined=false;', 'AndroidMTUMeasurementGate.release(lease);boolean joined=false;', 'held', 'selected draft released its owner or MTU before original cleanup joined:'),
        )
        for name, before, after, phase, witness in controls:
            key = APP + name + '.java'; source = original[key]
            if source.count(before) != 1:
                raise AssertionError('Selected draft causal guard lost its exact source: ' + before)
            target = src / key; target.write_text(source.replace(before, after)); compile()
            result = subprocess.run(run + [phase], capture_output=True, text=True, timeout=120)
            target.write_text(source)
            if result.returncode == 0 or witness not in result.stdout + result.stderr:
                raise AssertionError('Selected draft control missed ' + phase + '\n' + result.stdout + result.stderr)
            print('Compiled selected draft omission refused: ' + phase + '/' + name, flush=True)


def main():
    for family in ('ordinary', 'socks', 'connect', 'openvpn', 'multiple'):
        execute(family)


if __name__ == '__main__':
    if sys.argv[1:] == ['--bounded-child']:
        main()
    elif len(sys.argv) == 3 and sys.argv[1] == '--family':
        execute(sys.argv[2])
    elif sys.argv[1:]:
        raise SystemExit('unknown arguments')
    else:
        subprocess.run([sys.executable, __file__, '--bounded-child'], check=True, timeout=300)
