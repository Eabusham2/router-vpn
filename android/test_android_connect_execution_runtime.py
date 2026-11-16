#!/usr/bin/env python3
"""Exercise shipping CONNECT execution host/service/restore with explicit native doubles.

Shared source compilation and actual libbox factory gates are separate. These
checks do not claim Android TUN, encrypted traffic, or remote lease acceptance.
"""
from pathlib import Path
import os
import shutil
import subprocess
import tempfile
import test_android_node_chain_execution_runtime as HOST
import test_android_node_chain_execution_restore as RESTORE
import test_android_node_chain_connect_runtime as CONNECT


def once(value, before, after):
    if value.count(before)!=1:raise AssertionError('CONNECT host native seam changed: '+before)
    return value.replace(before,after)


def sources():
    result=RESTORE.sources()
    app,native=HOST.APP,HOST.NATIVE
    result[app+'AndroidNodeStore.java']=CONNECT.SOURCES[app+'AndroidNodeStore.java'].replace('final String execution="local";','String execution="local";boolean imported;')
    result[app+'AndroidNodeStore.java']=once(result[app+'AndroidNodeStore.java'],'volatile boolean valid=true;','String finalLayer="off";volatile boolean valid=true;')
    result.pop(app+'AndroidNodeChainCONNECTCapture.java')
    capture=CONNECT.SOURCES[app+'AndroidNodeChainCapture.java']
    capture=once(capture,'final String config,launchInput;','final String config,launchInput,selectionExecution;')
    capture=once(capture,'this.source=source;strict=source.strict;','this.source=source;selectionExecution=source.execution;strict=source.strict;')
    capture=once(capture,'"original-paired-"+i','i==source.members.size()-1?new org.json.JSONObject().put("mode","shadowsocks").put("profile_json",new org.json.JSONObject().put("start_layer",source.finalLayer).toString()).put("original_private_final","original-paired-"+i).toString():"original-paired-"+i')
    result[app+'AndroidNodeChainCapture.java']=capture
    result[native+'RouterNodeChainCONNECT.java']=CONNECT.SOURCES[native+'RouterNodeChainCONNECT.java']
    server=result[native+'CommandServer.java']
    result[native+'CommandServer.java']=once(server,'public void start(){started++;}','public boolean typed,bound;public void start(){if(typed&&!bound)throw new IllegalStateException("typed execution started before binding");started++;}')
    value=result[native+'RouterNodeChainExecution.java']
    value=once(value,'localSHA=original.getString("source_sha256");','localSHA="a".repeat(64);int count=original.getJSONArray("nodes").length();if(original.getInt("schema")!=4||count<3||count>8||original.getJSONArray("identity_sources").length()!=count)throw new IllegalStateException("wrong typed CONNECT fixture source");for(int i=0;i<count;i++)if(original.getJSONArray("identity_sources").getString(i).isEmpty()!=(i==count-2))throw new IllegalStateException("wrong original CONNECT private identity position");')
    value=value.replace('new JSONObject().put("schema",1).put("execution",requested)','new JSONObject().put("schema",4).put("execution",requested)').replace('routervpn-node-chain-execution-preparation-input','routervpn-node-chain-connect-execution-preparation-input')
    value=once(value,'public CommandServer newCommandServer(CommandServerHandler h,PlatformInterface p)throws Exception{throw new IllegalStateException("No typed CONNECT factory in ordinary execution fixture");}', '''public CommandServer factory;public int factories;
 public CommandServer newCommandServer(CommandServerHandler h,PlatformInterface p)throws Exception{if(factory!=null||closed||cancelled)throw new IllegalStateException("typed original factory retired");factories++;factory=new CommandServer(h,p);factory.typed=true;return factory;}''')
    value=once(value,'public void bindNative(CommandServer captured){binds++;','public void bindNative(CommandServer captured){binds++;if(captured!=factory||captured==null)throw new IllegalStateException("foreign typed execution factory");captured.bound=true;')
    result[native+'RouterNodeChainExecution.java']=value
    lib=result[native+'Libbox.java']
    lib=lib.replace('throw new IllegalStateException("No typed CONNECT preparation in ordinary fixture");','RouterNodeChainExecution.ordinaryPreparations++;return new RouterNodeChainExecution(source,requested);').replace('throw new IllegalStateException("No typed CONNECT Last in ordinary fixture");','RouterNodeChainExecution.lastPreparations++;return new RouterNodeChainExecution(source,requested,last);')
    lib=lib[:-1]+'public static RouterNodeChainCONNECT newRouterNodeChainCONNECT(String input){return new RouterNodeChainCONNECT(input);}}'
    result[native+'Libbox.java']=lib
    return result


def runtime_harness():
    value=HOST.HARNESS.replace('new boolean[]{false,true}', 'new boolean[]{false}').replace('new int[]{2,3,4,8}','new int[]{3,4,8}').replace('new int[]{3}', 'new int[]{3,4,8}').replace('new int[]{3,4,8}','new int[]{3,4,5,6,7,8}').replace('new Fixture(2,','new Fixture(3,')
    value=value.replace('value.capture.plan.failCloses=0;','value.capture.connect.plan.failClose=false;')
    value=value.replace('original.capture.plan.runs==0','original.capture.connect.plan.runs==0&&original.capture.connect.plan.factories==0&&plan.factories==1&&server.typed&&server.bound')
    value=value.replace('public static void main(String[] args)throws Exception{', r'''static void factoryControl()throws Exception{
  for(int count:new int[]{3,4,5,6,7,8})try(Fixture f=new Fixture(count,"server")){
   f.start();await(()->RouterNodeChainCONNECT.latest!=null&&(RouterNodeChainCONNECT.latest.factories!=0||RouterNodeChainExecution.latest!=null&&RouterNodeChainExecution.latest.factories!=0),"no original constructor entered");
   check(RouterNodeChainCONNECT.latest.factories==0,"typed execution factory borrowed dormant Local owner");
   await(()->f.runtime.isConnected(),"typed execution did not retain original proof");f.stop();
  }
 }
 public static void main(String[] args)throws Exception{if(args.length>0&&args[0].equals("factory")){factoryControl();return;}
''')
    value=once(value, 'localSource.getInt("schema")== (imported?2:1)', 'localSource.getInt("schema")==4')
    value=once(value, 'public static void main(String[] args)throws Exception{', 'public static void main(String[] args)throws Exception{RouterNodeChainCONNECT.transport=System.getProperty("routervpn.connect.protocol","http-connect");')
    return value


LAYER_HARNESS=r'''package com.eabusham.routervpn;
import io.nekohasekai.libbox.*;import org.json.*;import java.nio.file.*;
public final class CONNECTExecutionLayersRuntimeTest {
 static int checks;static void check(boolean value,String why){checks++;if(!value)throw new AssertionError(why);}
 static void retained(String source,int count,String layer)throws Exception{
  JSONObject original=new JSONObject(new JSONObject(source).getString("local_source"));JSONArray nodes=original.getJSONArray("nodes"),ids=original.getJSONArray("identity_sources");
  check(original.getInt("schema")==4&&nodes.length()==count&&ids.length()==count,"layered host lost original complete source");
  JSONObject last=new JSONObject(nodes.getString(count-1));check(last.getString("original_private_final").equals("original-paired-"+(count-1))&&new JSONObject(last.getString("profile_json")).getString("start_layer").equals(layer),"layered host replaced original final source");
  for(int i=0;i<count;i++)check(ids.getString(i).equals(i==count-2?"":"paired-identity-"+i),"layered host replaced original paired inventory");
 }
 public static void main(String[]args)throws Exception{
  RouterNodeChainCONNECT.transport=System.getProperty("routervpn.connect.protocol","http-connect");
  for(int count:new int[]{3,8})for(String layer:new String[]{"aes-256-gcm","aes-256-gcm+xor-whitening"})for(String variant:new String[]{"server/server","auto/server","auto/local"})try(var f=new OrderedExecutionRuntimeTest.Fixture(count,variant.split("/")[0])){
   String chosen=variant.split("/")[1];f.source.finalLayer=layer;RouterNodeChainExecution.configured=plan->plan.selected=chosen;f.connected();var original=f.owner();String source=original.execution.source;retained(source,count,layer);
   original.execution.plan.effectiveMTU=1360;var restore=f.runtime.captureRestore();String last=original.captureLastRecord();int ordinary=RouterNodeChainExecution.ordinaryPreparations;f.stop();
   RouterNodeChainExecution.configured=plan->plan.selected=chosen.equals("server")?"local":"server";
   var done=new OrderedExecutionRuntimeTest.Result();f.runtime.restore(restore,AndroidHomeStateStore.snapshot(f.service),done);done.finished();f.drain();var current=f.owner();
   check(done.ok&&current!=original&&current.source==f.source&&f.runtime.restoredMatches(restore),"layered host did not retain original restore owner");
   check(current.execution.source.equals(source)&&current.execution.execution().equals(chosen)&&current.execution.plan.runs==1,"layered restore changed final source or reran Compare");retained(current.execution.source,count,layer);
   check(new JSONObject(current.execution.config).getJSONArray("inbounds").getJSONObject(0).getInt("mtu")==1360&&Files.readString(current.directory.toPath().resolve("sing-box.json")).equals(current.execution.config),"layered restore staged a foreign final projection");f.stop();
   var cold=new OrderedExecutionRuntimeTest.Result();f.runtime.connectLast(f.source,AndroidHomeStateStore.snapshot(f.service),AndroidNodeChainSession.selection(f.service,f.source),chosen,last,cold);cold.finished();f.drain();
   check(cold.ok&&f.owner().execution.source.equals(source)&&f.owner().provedExecution().equals(chosen),"layered cold Last replaced original source or selected execution");
   check(RouterNodeChainExecution.ordinaryPreparations==ordinary&&f.owner().execution.plan.runs==1,"layered cold Last reran Compare");retained(f.owner().execution.source,count,layer);f.stop();
   f.source.finalLayer="off";var changed=new OrderedExecutionRuntimeTest.Result();f.runtime.connectLast(f.source,AndroidHomeStateStore.snapshot(f.service),AndroidNodeChainSession.selection(f.service,f.source),chosen,last,changed);changed.finished();f.drain();
   check(!changed.ok&&!f.runtime.isConnected(),"changed final layer borrowed original Last authority");
  }
  System.out.println("Android CONNECT independent final-layer lifecycle: "+checks+" shipping Java checks PASS; source/native/OS boundaries doubled");
 }
}
'''

def main():
    jar=Path(os.environ.get('ANDROID_JSON_JAR','/usr/share/java/com.android.json.jar'))
    if not jar.is_file() or not shutil.which('javac'):raise RuntimeError('Actual JDK and JSON required')
    with tempfile.TemporaryDirectory(prefix='routervpn-connect-execution-host-') as directory:
        work=Path(directory);src=work/'src'
        for path,value in sources().items():
            target=src/path;target.parent.mkdir(parents=True,exist_ok=True);target.write_text(value)
        app=src/HOST.APP
        names=('AndroidHomeStateStore','AndroidConnectionSelection','AndroidNodeChainCONNECTCapture','AndroidNodeChainExecutionCapture','AndroidNodeChainSession','AndroidNodeChainMTUPlatform','AndroidNodeChainRuntime','LayeredVpnService')
        original={name:(HOST.JAVA/(name+'.java')).read_text() for name in names}
        for name,value in original.items():(app/(name+'.java')).write_text(value)
        (app/'OrderedExecutionRuntimeTest.java').write_text(runtime_harness())
        (app/'CONNECTExecutionLayersRuntimeTest.java').write_text(LAYER_HARNESS)
        (app/'OrderedExecutionRestoreTest.java').write_text(RESTORE.HARNESS.replace('new boolean[]{false,true}', 'new boolean[]{false}').replace('new int[]{2,3,4,8}','new int[]{3,4,8}').replace('new int[]{3,4,8}','new int[]{3,4,5,6,7,8}').replace('public static void main(String[] args)throws Exception{','public static void main(String[] args)throws Exception{RouterNodeChainCONNECT.transport=System.getProperty("routervpn.connect.protocol","http-connect");'))
        classes=work/'classes';subprocess.run(['javac','--release','17','-encoding','UTF-8','-proc:none','-cp',str(jar),'-d',str(classes),*map(str,src.rglob('*.java'))],check=True,timeout=60)
        cp=os.pathsep.join((str(classes),str(jar)))
        for transport in ('http-connect','https-connect'):
            for root in ('OrderedExecutionRuntimeTest','OrderedExecutionRestoreTest','CONNECTExecutionLayersRuntimeTest'):
                subprocess.run(['java','-Droutervpn.connect.protocol='+transport,'-cp',cp,'com.eabusham.routervpn.'+root],check=True,timeout=120)
        controls=(
          ('AndroidNodeChainSession','if(execution!=null&&capture.connect!=null)return execution.plan.newCommandServer(handler,platform);','if(execution!=null&&capture.connect!=null)return capture.connect.plan.newCommandServer(handler,platform);','OrderedExecutionRuntimeTest','factory','typed execution factory borrowed dormant Local owner'),
          ('AndroidNodeChainSession','if(execution==null&&capture.connect!=null)capture.connect.plan.run(server);','if(capture.connect!=null)capture.connect.plan.run(server);','OrderedExecutionRuntimeTest','success','execution did not connect'),
          ('AndroidNodeChainExecutionCapture','if (restore != null) plan.requireRestore(restore.nativeCapture);','','OrderedExecutionRestoreTest','foreign','foreign typed restore reached native startup: object'),
        )
        for n,(name,before,after,root,phase,witness) in enumerate(controls):
            if before not in original[name]:raise AssertionError('CONNECT causal source seam changed')
            target=work/('mutant-'+str(n))/(name+'.java');target.parent.mkdir();target.write_text(original[name].replace(before,after));out=work/('negative-'+str(n));shutil.copytree(classes,out);mutantcp=os.pathsep.join((str(out),str(jar)))
            subprocess.run(['javac','--release','17','-proc:none','-cp',mutantcp,'-d',str(out),str(target)],check=True,timeout=60)
            result=subprocess.run(['java','-cp',mutantcp,'com.eabusham.routervpn.'+root,phase],text=True,capture_output=True,timeout=120)
            if result.returncode!=1 or witness not in result.stderr:raise AssertionError('CONNECT causal witness missing: '+witness+'\n'+result.stdout+result.stderr)
            print('CONNECT execution host causal refusal: '+witness,flush=True)

if __name__=='__main__':main()
