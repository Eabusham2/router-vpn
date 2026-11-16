#!/usr/bin/env python3
"""Exercise shipping SOCKS execution host/service/restore with explicit native doubles.

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
import test_android_node_chain_socks_runtime as SOCKS


def once(value, before, after):
    if value.count(before)!=1:raise AssertionError('SOCKS host native seam changed: '+before)
    return value.replace(before,after)


def sources():
    result=RESTORE.sources()
    app,native=HOST.APP,HOST.NATIVE
    result[app+'AndroidNodeStore.java']=SOCKS.SOURCES[app+'AndroidNodeStore.java'].replace('final String execution="local";','String execution="local";boolean imported;')
    result.pop(app+'AndroidNodeChainSOCKSCapture.java')
    capture=SOCKS.SOURCES[app+'AndroidNodeChainCapture.java']
    capture=once(capture,'final String config,launchInput;','final String config,launchInput,selectionExecution;')
    capture=once(capture,'this.source=source;strict=source.strict;','this.source=source;selectionExecution=source.execution;strict=source.strict;')
    result[app+'AndroidNodeChainCapture.java']=capture
    result[native+'RouterNodeChainSOCKS.java']=SOCKS.SOURCES[native+'RouterNodeChainSOCKS.java']
    server=result[native+'CommandServer.java']
    result[native+'CommandServer.java']=once(server,'public void start(){started++;}','public boolean typed,bound;public void start(){if(typed&&!bound)throw new IllegalStateException("typed execution started before binding");started++;}')
    value=result[native+'RouterNodeChainExecution.java']
    value=once(value,'localSHA=original.getString("source_sha256");','localSHA="a".repeat(64);int count=original.getJSONArray("nodes").length();if(original.getInt("schema")!=3||count<3||count>8||original.getJSONArray("identity_sources").length()!=count)throw new IllegalStateException("wrong typed SOCKS fixture source");for(int i=0;i<count;i++)if(original.getJSONArray("identity_sources").getString(i).isEmpty()!=(i==count-2))throw new IllegalStateException("wrong original SOCKS private identity position");')
    value=value.replace('new JSONObject().put("schema",1).put("execution","local")','new JSONObject().put("schema",3).put("execution","local")').replace('new JSONObject().put("schema",1).put("execution",requested)','new JSONObject().put("schema",3).put("execution",requested)').replace('routervpn-node-chain-execution-preparation-input','routervpn-node-chain-socks-execution-preparation-input')
    value=once(value,'public CommandServer newCommandServer(CommandServerHandler h,PlatformInterface p)throws Exception{throw new IllegalStateException("No typed CONNECT factory in ordinary execution fixture");}', '''public CommandServer newCommandServer(CommandServerHandler h,PlatformInterface p)throws Exception{throw new IllegalStateException("No typed CONNECT factory in SOCKS execution fixture");}
 public CommandServer factory;public int factories;
 public CommandServer socksCommandServer(CommandServerHandler h,PlatformInterface p)throws Exception{if(factory!=null||closed||cancelled)throw new IllegalStateException("typed original factory retired");factories++;factory=new CommandServer(h,p);factory.typed=true;return factory;}''')
    value=once(value,'public void bindNative(CommandServer captured){binds++;','public void bindNative(CommandServer captured){binds++;if(captured!=factory||captured==null)throw new IllegalStateException("foreign typed execution factory");captured.bound=true;')
    result[native+'RouterNodeChainExecution.java']=value
    lib=result[native+'Libbox.java']
    lib=lib.replace('throw new IllegalStateException("No typed SOCKS preparation in ordinary fixture");','RouterNodeChainExecution.ordinaryPreparations++;return new RouterNodeChainExecution(source,requested);').replace('throw new IllegalStateException("No typed SOCKS Last in ordinary fixture");','RouterNodeChainExecution.lastPreparations++;return new RouterNodeChainExecution(source,requested,last);')
    lib=once(lib,'throw new IllegalStateException("No typed SOCKS factory in ordinary fixture");','return plan.socksCommandServer(h,p);')
    lib=lib[:-1]+'public static RouterNodeChainSOCKS newRouterNodeChainSOCKS(String input){return new RouterNodeChainSOCKS(input);}}'
    result[native+'Libbox.java']=lib
    return result


def runtime_harness():
    value=HOST.HARNESS.replace('new boolean[]{false,true}', 'new boolean[]{false}').replace('new int[]{2,3,4,8}','new int[]{3,4,8}').replace('new int[]{3}', 'new int[]{3,4,8}').replace('new Fixture(2,','new Fixture(3,')
    value=value.replace('value.capture.plan.failCloses=0;','value.capture.socks.plan.failClose=false;')
    value=value.replace('original.capture.plan.runs==0','original.capture.socks.plan.runs==0&&original.capture.socks.plan.factories==0&&plan.factories==1&&server.typed&&server.bound')
    value=value.replace('public static void main(String[] args)throws Exception{', r'''static void factoryControl()throws Exception{
  for(int count:new int[]{3,4,8})try(Fixture f=new Fixture(count,"server")){
   f.start();await(()->RouterNodeChainSOCKS.latest!=null&&(RouterNodeChainSOCKS.latest.factories!=0||RouterNodeChainExecution.latest!=null&&RouterNodeChainExecution.latest.factories!=0),"no original constructor entered");
   check(RouterNodeChainSOCKS.latest.factories==0,"typed execution factory borrowed dormant Local owner");
   await(()->f.runtime.isConnected(),"typed execution did not retain original proof");f.stop();
  }
 }
 public static void main(String[] args)throws Exception{if(args.length>0&&args[0].equals("factory")){factoryControl();return;}
''')
    value=once(value, 'localSource.getInt("schema")== (imported?2:1)', 'localSource.getInt("schema")==3')
    return value


def main():
    jar=Path(os.environ.get('ANDROID_JSON_JAR','/usr/share/java/com.android.json.jar'))
    if not jar.is_file() or not shutil.which('javac'):raise RuntimeError('Actual JDK and JSON required')
    with tempfile.TemporaryDirectory(prefix='routervpn-socks-execution-host-') as directory:
        work=Path(directory);src=work/'src'
        for path,value in sources().items():
            target=src/path;target.parent.mkdir(parents=True,exist_ok=True);target.write_text(value)
        app=src/HOST.APP
        names=('AndroidHomeStateStore','AndroidConnectionSelection','AndroidNodeChainSOCKSCapture','AndroidNodeChainExecutionCapture','AndroidNodeChainSession','AndroidNodeChainMTUPlatform','AndroidNodeChainRuntime','LayeredVpnService')
        original={name:(HOST.JAVA/(name+'.java')).read_text() for name in names}
        for name,value in original.items():(app/(name+'.java')).write_text(value)
        (app/'OrderedExecutionRuntimeTest.java').write_text(runtime_harness())
        (app/'OrderedExecutionRestoreTest.java').write_text(RESTORE.HARNESS.replace('new boolean[]{false,true}', 'new boolean[]{false}').replace('new int[]{2,3,4,8}','new int[]{3,4,8}'))
        classes=work/'classes';subprocess.run(['javac','--release','17','-encoding','UTF-8','-proc:none','-cp',str(jar),'-d',str(classes),*map(str,src.rglob('*.java'))],check=True,timeout=60)
        cp=os.pathsep.join((str(classes),str(jar)))
        for root in ('OrderedExecutionRuntimeTest','OrderedExecutionRestoreTest'):
            subprocess.run(['java','-cp',cp,'com.eabusham.routervpn.'+root],check=True,timeout=120)
        controls=(
          ('AndroidNodeChainSession','if(execution!=null&&capture.socks!=null)return Libbox.routerNodeChainSOCKSExecutionNewCommandServer(execution.plan,handler,platform);','if(execution!=null&&capture.socks!=null)return capture.socks.plan.newCommandServer(handler,platform);','OrderedExecutionRuntimeTest','factory','typed execution factory borrowed dormant Local owner'),
          ('AndroidNodeChainSession','else if(execution==null&&capture.socks!=null)capture.socks.plan.run(server);','else if(capture.socks!=null)capture.socks.plan.run(server);','OrderedExecutionRuntimeTest','success','execution did not connect'),
          ('AndroidNodeChainExecutionCapture','if (restore != null) plan.requireRestore(restore.nativeCapture);','','OrderedExecutionRestoreTest','foreign','foreign typed restore reached native startup: object'),
        )
        for n,(name,before,after,root,phase,witness) in enumerate(controls):
            if before not in original[name]:raise AssertionError('SOCKS causal source seam changed')
            target=work/('mutant-'+str(n))/(name+'.java');target.parent.mkdir();target.write_text(original[name].replace(before,after));out=work/('negative-'+str(n));shutil.copytree(classes,out);mutantcp=os.pathsep.join((str(out),str(jar)))
            subprocess.run(['javac','--release','17','-proc:none','-cp',mutantcp,'-d',str(out),str(target)],check=True,timeout=60)
            result=subprocess.run(['java','-cp',mutantcp,'com.eabusham.routervpn.'+root,phase],text=True,capture_output=True,timeout=120)
            if result.returncode!=1 or witness not in result.stderr:raise AssertionError('SOCKS causal witness missing: '+witness+'\n'+result.stdout+result.stderr)
            print('SOCKS execution host causal refusal: '+witness,flush=True)

if __name__=='__main__':main()
