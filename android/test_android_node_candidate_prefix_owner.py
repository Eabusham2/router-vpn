#!/usr/bin/env python3
"""Execute actual process helper/measurement/service prefix-only composition.

The source/native interfaces are explicit lifecycle boundaries. The mandatory
source and native gates separately prove sealed compilation, closed ingress,
actual prefix HTTP proof calls and fifty TCP calls; this is host ownership only.
"""
from pathlib import Path
import importlib.util
import os
import shutil
import subprocess
import tempfile

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('prefix_supervisor_base',ROOT/'android/test_android_node_candidate_preparation_owner.py')
owner=importlib.util.module_from_spec(spec);spec.loader.exec_module(owner)
base=owner.base;APP=owner.APP;NATIVE=owner.NATIVE
SOURCES=dict(owner.SOURCES)
SOURCES[NATIVE+'RouterNodeChainCandidateMeasurement.java']=SOURCES[NATIVE+'RouterNodeChainCandidateMeasurement.java'].replace('volatile int starts,closes;', 'volatile int starts,closes,drains;')
SOURCES[APP+'AndroidMTUSession.java']=SOURCES[APP+'AndroidMTUSession.java'].replace('candidatePrefixCurrent(AndroidNodeChainSession source){return false;}','candidatePrefixCurrent(AndroidNodeChainSession source){return true;}').replace('activateNodeChain(source);if(failure!=null)throw failure;', 'if(source.candidatePrefix==null)activateNodeChain(source);else if(!source.prefixHealthy())throw new IllegalStateException("No prefix proof");if(failure!=null)throw failure;')
SOURCES[APP+'AndroidNodeCandidatePrefixCapture.java']=SOURCES[APP+'AndroidNodeCandidatePrefixCapture.java'].replace('throw new IllegalStateException("No independent prefix in the complete-saved fallback fixture");','original.plan.valid=false;return new AndroidNodeCandidatePrefixCapture(original,prefix,inventory);')
SOURCES[APP+'AndroidNodeCandidateCatalog.java']=r'''package com.eabusham.routervpn;final class AndroidNodeCandidateCatalog {
 static volatile boolean sourcesValid=true;final AndroidNodeStore.ChainCapture originalSource;final int prefix;final String inventory="original inventory";
 AndroidNodeChainSession session;io.nekohasekai.libbox.CommandServer server;
 static final class Row{final String id,name,input="original input";Row(String id){this.id=id;name=id;}}
 final java.util.List<Row> rows=java.util.List.of(new Row("one"),new Row("two"));
 private AndroidNodeCandidateCatalog(AndroidNodeStore.ChainCapture source,int prefix){originalSource=source;this.prefix=prefix;}
 AndroidNodeCandidateCatalog(android.content.Context c,AndroidNodeChainSession session,int prefix)throws Exception{this(session.source,prefix);bind(session);}
 static AndroidNodeCandidateCatalog captureSources(android.content.Context c,AndroidNodeStore.ChainCapture source,int prefix){return new AndroidNodeCandidateCatalog(source,prefix);}
 void bind(AndroidNodeChainSession value)throws Exception{requireSourcesCurrent();if(session!=null||value.source!=originalSource)throw new IllegalStateException("Replaced prefix catalog");session=value;server=value.candidateServer();}
 void requireSourcesCurrent(){originalSource.requireCurrent();requireSavedSourcesCurrent();}
 void requireCurrent(){try{requireSourcesCurrent();if(session==null||session.candidateServer()!=server)throw new IllegalStateException("Missing original prefix binding");}catch(Exception failure){throw new IllegalStateException(failure);}}
 void requireSavedSourcesCurrent(){if(!sourcesValid)throw new IllegalStateException("captured saved catalog changed away and back");}
}'''
SOURCES[NATIVE+'RouterNodeChainCandidatePreparation.java']=r'''package io.nekohasekai.libbox;
public class RouterNodeChainCandidatePreparation {
 public CommandServer server;public boolean cancelled,closed,proved;public int binds,runs,closes;public Runnable afterRun,beforeClose;
 private RouterNodeChainCandidateMeasurement measurement;
 public void bindNative(CommandServer original)throws Exception{if(server!=null)throw new IllegalStateException("Duplicate native binding");server=original;binds++;if(cancelled)throw new IllegalStateException("Retired binding");}
 public void run(CommandServer original,Object catalog)throws Exception{if(server!=original||cancelled)throw new IllegalStateException("Foreign original prefix");measurement=new RouterNodeChainCandidateMeasurement();proved=true;runs++;if(afterRun!=null)afterRun.run();}
 public boolean healthy(){return proved&&!cancelled&&!closed&&server!=null&&!server.closed;}
 public String metadata()throws Exception{return new org.json.JSONObject(measurement.metadata()).put("source_sha256","f".repeat(64)).put("config_sha256","6".repeat(64)).toString();}
 public String captureSHA256(){return "c".repeat(64);}public String progressJSON(){return "{}";}
 public void start(String request,String candidate)throws Exception{if(!healthy())throw new IllegalStateException("Retired prefix");measurement.start(request,candidate);}
 public void cancel(String request){if(measurement!=null)measurement.cancel(request);}public void drain(String request)throws Exception{measurement.drains++;if(RouterNodeChainCandidateMeasurement.holdClose)throw new IllegalStateException("original candidate drain pending");measurement.drain(request);}
 public String statusJSON()throws Exception{return measurement.statusJSON();}
 public void networkChanged(){cancelled=true;}
 public void close()throws Exception{closes++;if(beforeClose!=null)beforeClose.run();if(measurement!=null)measurement.close();cancelled=true;closed=true;}
 public boolean nativeClosed(){return closed&&server!=null&&server.closed;}
}'''

CASES=owner.CASES.replace('AndroidNodeChainSession.selection(f.service,f.source),2,callback);','AndroidNodeChainSession.selection(f.service,f.source),0,callback);').replace('RouterNodeChain.configured=plan->plan.afterRun=()->plan.server.failClose=true;', '((AndroidNodeCandidatePrefixCapture)get(operation,"capturedPrefix")).plan.afterRun=()->{try{((AndroidNodeCandidatePrefixCapture)get(operation,"capturedPrefix")).plan.server.failClose=true;}catch(Exception failure){throw new IllegalStateException(failure);}};')
CASES=CASES.replace('check(AndroidNodeCandidatePreparation.busy()&&AndroidMTUMeasurementGate.held()&&f.owner()==null,', 'check(operation.prefixOnly(),"prefix purpose was not captured before permission");\n   check(operation.testsSavedPosition(0)&&!operation.testsSavedPosition(1),"prefix display borrowed the saved suffix");\n   var captured=(AndroidNodeCandidatePrefixCapture)get(operation,"capturedPrefix");check(captured.original.plan.runs==0&&captured.plan.binds==0,"permission capture started the old final or a native server");\n   var prematureClose=new java.util.concurrent.atomic.AtomicBoolean();captured.plan.beforeClose=()->{try{var worker=(AndroidNodeCandidateMeasurement)get(operation,"measurement");if(worker==null||!worker.joined())prematureClose.set(true);}catch(Exception failure){throw new IllegalStateException(failure);}};\n   check(AndroidNodeCandidatePreparation.busy()&&AndroidMTUMeasurementGate.held()&&f.owner()==null,')
CASES=CASES.replace('check(callback.failure==null&&callback.choices.size()==2,"temporary candidate batch did not return complete post-DOWN choices");', 'check(callback.failure==null&&callback.choices.size()==2,"prefix candidate batch did not return complete post-DOWN choices: "+callback.failure);\n   check(!prematureClose.get(),"borrowed worker retired prefix proof before outer teardown");\n   check(captured.original.plan.runs==0&&captured.plan.runs==1&&captured.plan.nativeClosed(),"prefix result borrowed old final proof or omitted original native DOWN");')
CASES=CASES.replace('RouterNodeChainCandidateMeasurement.latest.closes>0,"held candidate close was not entered"','(RouterNodeChainCandidateMeasurement.latest.drains>1||RouterNodeChainCandidateMeasurement.latest.closes>0),"held candidate drain was not entered"')
CASES=CASES.replace('var session=f.owner();var server=(CommandServer)get(f.service,"commandServer");f.service.onRevoke();f.drain();', 'var session=f.owner();var server=(CommandServer)get(f.service,"commandServer");\n   boolean premature=((AndroidNodeCandidateMeasurement)get(operation,"measurement")).joined();\n   if(premature)RouterNodeChainCandidateMeasurement.holdClose=false; // Release the injected hold before failing into fixture teardown.\n   check(!premature,"prefix measurement acknowledged join before original callbacks");\n   f.service.onRevoke();f.drain();')
CASES=CASES.replace('"Android temporary candidate process owner: "', '"Android prefix candidate process owner: "')


def main():
    jar=Path(os.environ.get('ANDROID_JSON_JAR','/usr/share/java/com.android.json.jar'))
    if not jar.is_file() or not shutil.which('javac'):raise RuntimeError('JDK17 and Android JSON required')
    with tempfile.TemporaryDirectory(prefix='routervpn-prefix-owner-') as directory:
        work=Path(directory);src=work/'src'
        for path,text in SOURCES.items():
            target=src/path;target.parent.mkdir(parents=True,exist_ok=True);target.write_text(text)
        app=src/APP
        names=('AndroidHomeStateStore','AndroidConnectionSelection','AndroidNodeChainSession','AndroidNodeChainMTUPlatform','AndroidNodeChainRuntime','LayeredVpnService','AndroidMTUMeasurementGate','AndroidNodeCandidateMeasurement','AndroidNodeCandidateResult','AndroidNodeCandidatePreparation')
        originals={name:(base.JAVA/(name+'.java')).read_text() for name in names}
        for name,text in originals.items():(app/(name+'.java')).write_text(text)
        (app/'OrderedRuntimeTest.java').write_text(base.HARNESS.split(' public static void main(String[] args)throws Exception {')[0]+CASES)
        classes=work/'classes';cp=os.pathsep.join((str(classes),str(jar)))
        subprocess.run(['javac','--release','17','-encoding','UTF-8','-proc:none','-cp',str(jar),'-d',str(classes),*map(str,src.rglob('*.java'))],check=True,timeout=60)
        subprocess.run(['java','-cp',cp,'com.eabusham.routervpn.OrderedRuntimeTest'],check=True,timeout=120)
        controls=(
            ('AndroidNodeCandidatePreparation','if(packetPrefix(source,prefix)){','if(false){','complete','prefix purpose was not captured before permission'),
            ('AndroidNodeCandidatePreparation','},owner.capturedPrefix,owner.capturedPrefix==null?null:owner.catalog);','},null,null);','complete','prefix candidate batch did not return complete post-DOWN choices:'),
            ('AndroidNodeCandidateMeasurement','AndroidNodeCandidatePrefixCapture prefix=catalog.session.candidatePrefix;','AndroidNodeCandidatePrefixCapture prefix=null;','complete','prefix candidate batch did not return complete post-DOWN choices:'),
            ('AndroidNodeCandidateMeasurement','else if(!admittedRequest.isEmpty())prefix.drain(admittedRequest);','else {}','revoke','prefix measurement acknowledged join before original callbacks'),
            ('AndroidNodeCandidateMeasurement','else if(!admittedRequest.isEmpty())prefix.drain(admittedRequest);','else prefix.close();','complete','borrowed worker retired prefix proof before outer teardown'),
            ('AndroidNodeCandidatePreparation','boolean joined=false;','AndroidMTUMeasurementGate.release(lease);boolean joined=false;','graph-join','inner candidate join released outer hold before failed graph close'),
            ('AndroidNodeCandidatePreparation','network.requireProved(LayeredVpnService.prepareNodeCandidates(session,lease));','LayeredVpnService.prepareNodeCandidates(session,lease);','complete','temporary candidates bypassed the real native host or complete inventory'),
            ('AndroidNodeCandidatePreparation','catalog.requireSavedSourcesCurrent();','','complete','post-DOWN candidate ignored captured catalog changes'),
        )
        for index,(name,before,after,family,witness) in enumerate(controls):
            if originals[name].count(before)!=1:raise AssertionError('Exact prefix supervisor seam changed: '+before)
            out=work/('negative-'+str(index));shutil.copytree(classes,out);mutation=work/('mutant-'+str(index))/(name+'.java');mutation.parent.mkdir();mutation.write_text(originals[name].replace(before,after));cp=os.pathsep.join((str(out),str(jar)))
            subprocess.run(['javac','--release','17','-encoding','UTF-8','-proc:none','-cp',cp,'-d',str(out),str(mutation)],check=True,timeout=60)
            result=subprocess.run(['java','-cp',cp,'com.eabusham.routervpn.OrderedRuntimeTest',family],text=True,capture_output=True,timeout=90)
            if result.returncode==0 or witness not in result.stderr:raise AssertionError('Prefix supervisor missed '+witness+'\n'+result.stdout+'\n'+result.stderr)
            print('Android prefix supervisor rejected: '+witness,flush=True)


if __name__=='__main__':main()
