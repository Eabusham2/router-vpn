#!/usr/bin/env python3
"""Run shipping Android typed restore against explicit native capsule doubles.

The complete Session/Runtime/Home/service and capture wrapper execute. The
native source, issued MTU readback, opaque capsule and OS are controlled native
boundaries; actual shared/native restore semantics have their separate gates.
This is host ownership evidence, not Android VPN/encrypted path acceptance.
"""
from pathlib import Path
import os
import shutil
import subprocess
import tempfile

import test_android_node_chain_execution_runtime as HOST


def once(text, before, after):
    if text.count(before) != 1:
        raise AssertionError('Typed restore fixture lost exact native seam: ' + before)
    return text.replace(before, after)


def sources():
    result = HOST.sources()
    native = result[HOST.NATIVE + 'RouterNodeChainExecution.java']
    native = once(native, 'public final String localLaunch,requested,source,config,sourceSHA,configSHA,localSHA,launch;',
                  'public String localLaunch,requested,source,config,sourceSHA,configSHA,localSHA,launch;public int effectiveMTU=1500;public RouterNodeChainExecutionRestoreCapture issuedRestore;')
    native = once(native, 'return new RouterNodeChainExecutionRestoreCapture(this,selected);',
                  'if(issuedRestore==null)issuedRestore=new RouterNodeChainExecutionRestoreCapture(this,selected);return issuedRestore;')
    native = once(native, 'public void requireRestore(RouterNodeChainExecutionRestoreCapture capture){if(capture==null||restore!=capture||capture.original==this||!capture.original.nativeClosed())throw new IllegalStateException("foreign or unjoined native restore capsule");}',
                  '''public void requireRestore(RouterNodeChainExecutionRestoreCapture capture)throws Exception{
 if(capture==null||restore!=capture||capture.original==this||!capture.original.nativeClosed()||capture.replacement!=this||effectiveMTU!=capture.mtu||new JSONObject(config).getJSONArray("inbounds").getJSONObject(0).getInt("mtu")!=capture.mtu)
 throw new IllegalStateException("foreign or unjoined native restore capsule");}''')
    result[HOST.NATIVE + 'RouterNodeChainExecution.java'] = native
    result[HOST.NATIVE + 'RouterNodeChainExecutionRestoreCapture.java'] = '''package io.nekohasekai.libbox;
public final class RouterNodeChainExecutionRestoreCapture {
 final RouterNodeChainExecution original;final String selected;final int mtu;RouterNodeChainExecution replacement;
 RouterNodeChainExecutionRestoreCapture(RouterNodeChainExecution original,String selected){this.original=original;this.selected=selected;mtu=original.effectiveMTU;}
}'''
    lib = result[HOST.NATIVE + 'Libbox.java']
    lib = once(lib, 'public static RouterNodeChainExecution newRouterNodeChainExecutionRestore(',
               'public static java.util.function.Consumer<RouterNodeChainExecution> afterRestore;\n public static RouterNodeChainExecution newRouterNodeChainExecutionRestore(')
    lib = once(lib, 'result.restore=capture;result.selected=capture.selected;return result;', '''result.restore=capture;result.selected=capture.selected;result.effectiveMTU=capture.mtu;
  org.json.JSONObject graph=new org.json.JSONObject(result.config);graph.getJSONArray("inbounds").getJSONObject(0).put("mtu",capture.mtu);result.config=graph.toString();result.configSHA=RouterNodeChainExecution.digest(result.config);
  result.launch=new org.json.JSONObject(result.launch).put("config_sha256",result.configSHA).toString();capture.replacement=result;
  if(afterRestore!=null)afterRestore.accept(result);return result;''')
    result[HOST.NATIVE + 'Libbox.java'] = lib
    return result


HARNESS = r'''package com.eabusham.routervpn;
import io.nekohasekai.libbox.*;import org.json.*;import java.nio.file.*;
public final class OrderedExecutionRestoreTest {
 static int checks;interface Action{void run()throws Exception;}static void check(boolean value,String why){checks++;if(!value)throw new AssertionError(why);}
 static void reject(Action action,String why)throws Exception{try{action.run();}catch(Exception expected){checks++;return;}throw new AssertionError(why);}
 static void effective()throws Exception{
  for(int count:new int[]{2,3,4,8})for(String mode:new String[]{"server/server","auto/server","auto/local"})try(var f=new OrderedExecutionRuntimeTest.Fixture(count,mode.split("/")[0])){
   String choice=mode.split("/")[1];RouterNodeChainExecution.configured=plan->plan.selected=choice;f.connected();var original=f.owner();var plan=original.execution.plan;plan.effectiveMTU=1360;
   var restore=f.runtime.captureRestore();var another=f.runtime.captureRestore();String source=original.execution.source,config=original.execution.config,sha=original.execution.configSHA256;
   plan.effectiveMTU=1440;f.stop();RouterNodeChainExecution.configured=next->next.selected=choice.equals("server")?"local":"server";
   var done=new OrderedExecutionRuntimeTest.Result();f.runtime.restore(restore,AndroidHomeStateStore.snapshot(f.service),done);done.finished();f.drain();var current=f.owner();
   check(done.ok&&current!=null&&current!=original&&f.runtime.restoredMatches(restore),"effective-MTU restore failed its exact original capsule");
   check(current.restoringExecution&&current.source==original.source&&current.execution.source.equals(source),"typed restore changed original source or replayed fresh launch policy");
   check(!current.execution.config.equals(config)&&!current.execution.configSHA256.equals(sha)&&new JSONObject(current.execution.config).getJSONArray("inbounds").getJSONObject(0).getInt("mtu")==1360,"typed restore substituted initial or later mutable MTU");
   check(current.execution.plan.runs==1&&current.execution.execution().equals(choice),"temporary restore reran Compare or replayed old proof");
   check(Files.readString(current.directory.toPath().resolve("sing-box.json")).equals(current.execution.config),"service staged initial Local config instead of typed restore projection");
   check(!f.runtime.restoredMatches(another),"same-source unrelated restore capture borrowed returned object");
   f.stop();
  }
 }
 static void foreign()throws Exception{
  for(String fault:new String[]{"object","mtu","native-close"})try(var f=new OrderedExecutionRuntimeTest.Fixture(3,"auto")){
   f.connected();var original=f.owner();original.execution.plan.effectiveMTU=1360;var restore=f.runtime.captureRestore();f.stop();int created=CommandServer.created;
   if(fault.equals("native-close"))original.execution.plan.nativeReceipt=false;
   else Libbox.afterRestore=plan->{if(fault.equals("object"))plan.restore=null;else plan.effectiveMTU=1440;};
   try{
    var done=new OrderedExecutionRuntimeTest.Result();f.runtime.restore(restore,AndroidHomeStateStore.snapshot(f.service),done);done.finished();f.drain();
    check(!done.ok&&CommandServer.created==created&&!f.runtime.isConnected(),"foreign typed restore reached native startup: "+fault);
    check(!f.runtime.isActiveOrTransitioning(),"rejected pure restore lost cleanup owner: "+fault);
   }finally{Libbox.afterRestore=null;original.execution.plan.nativeReceipt=true;}
  }
 }
 public static void main(String[] args)throws Exception{String family=args.length==0?"all":args[0];if(family.equals("all")||family.equals("effective"))effective();if(family.equals("all")||family.equals("foreign"))foreign();System.out.println("Android execution typed restore: "+checks+" shipping Java checks PASS; native capsules/OS doubled");}
}
'''


def main():
    jar = Path(os.environ.get('ANDROID_JSON_JAR', '/usr/share/java/com.android.json.jar'))
    if not jar.is_file() or not shutil.which('javac'):
        raise RuntimeError('JDK and actual Android JSON library required')
    with tempfile.TemporaryDirectory(prefix='routervpn-execution-restore-') as directory:
        work = Path(directory)
        src = work / 'src'
        for path, text in sources().items():
            target = src / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(text)
        app = src / HOST.APP
        names = ('AndroidHomeStateStore', 'AndroidConnectionSelection', 'AndroidNodeChainExecutionCapture',
                 'AndroidNodeChainSession', 'AndroidNodeChainMTUPlatform', 'AndroidNodeChainRuntime', 'LayeredVpnService')
        original = {}
        for name in names:
            original[name] = (HOST.JAVA / (name + '.java')).read_text()
            (app / (name + '.java')).write_text(original[name])
        (app / 'OrderedExecutionRuntimeTest.java').write_text(HOST.HARNESS)
        (app / 'OrderedExecutionRestoreTest.java').write_text(HARNESS)
        classes = work / 'classes'
        subprocess.run(['javac', '--release', '17', '-encoding', 'UTF-8', '-proc:none', '-cp', str(jar),
                        '-d', str(classes), *map(str, src.rglob('*.java'))], check=True, timeout=60)
        cp = os.pathsep.join((str(classes), str(jar)))
        subprocess.run(['java', '-cp', cp, 'com.eabusham.routervpn.OrderedExecutionRestoreTest'], check=True, timeout=120)
        capture = original['AndroidNodeChainExecutionCapture']
        controls = (
            (capture.replace('if (restore != null) plan.requireRestore(restore.nativeCapture);', ''),
             'foreign', 'foreign typed restore reached native startup: object'),
            (capture.replace('captured == null || restoredFrom != captured', 'captured == null'),
             'effective', 'same-source unrelated restore capture borrowed returned object'),
            (capture.replace('!captured.original.source.equals(result.source) || !captured.original.requested.equals(result.requested)',
                             '!captured.original.source.equals(result.source) || !captured.original.config.equals(result.config)'),
             'effective', 'effective-MTU restore failed its exact original capsule'),
        )
        for number, (changed, family, witness) in enumerate(controls):
            if changed == capture:
                raise AssertionError('Typed restore control lost shipping seam: ' + family)
            out = work / ('negative-' + str(number))
            shutil.copytree(classes, out)
            target = work / ('mutation-' + str(number)) / 'AndroidNodeChainExecutionCapture.java'
            target.parent.mkdir()
            target.write_text(changed)
            cp = os.pathsep.join((str(out), str(jar)))
            subprocess.run(['javac', '--release', '17', '-encoding', 'UTF-8', '-proc:none', '-cp', cp,
                            '-d', str(out), str(target)], check=True, timeout=60)
            result = subprocess.run(['java', '-cp', cp, 'com.eabusham.routervpn.OrderedExecutionRestoreTest', family],
                                    capture_output=True, text=True, timeout=120)
            if result.returncode == 0 or witness not in result.stderr:
                raise AssertionError('Typed restore control missed exact witness: ' + witness + '\n' + result.stdout + result.stderr)
            print('Android typed restore causal control rejected: ' + family, flush=True)


if __name__ == '__main__':
    main()
