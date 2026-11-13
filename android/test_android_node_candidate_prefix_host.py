#!/usr/bin/env python3
"""Execute the real Android service/session/runtime prefix-purpose lifecycle.

OS, MTU readback and libbox handles are explicit boundaries. Native prefix proof,
fifty-probe and construction receipts have their separate mandatory native gate;
this host gate does not claim encrypted packet or device acceptance.
"""
from pathlib import Path
import importlib.util
import os
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('prefix_host_base', ROOT/'android/test_android_node_chain_runtime.py')
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)

CASES = r'''
 static final class Guard implements AndroidNodeChainRuntime.TemporaryGuard {
  boolean join=true;int drains,cancels;public void requireCurrent(){}public void cancel(){cancels++;}public boolean drain(){drains++;return join;}
 }
 static final class Prefix {
  final Guard guard=new Guard();final Result result=new Result();final AndroidNodeChainCapture source;
  final AndroidNodeCandidateCatalog catalog;final AndroidNodeCandidatePrefixCapture capture;final AndroidNodeChainRuntime.Temporary token;
  Prefix(Fixture f)throws Exception{
   source=AndroidNodeChainCapture.compile(f.source);source.plan.valid=false; // Old final is deliberately unusable.
   catalog=new AndroidNodeCandidateCatalog(f.source,f.source.members.size()-2);
   capture=new AndroidNodeCandidatePrefixCapture(source,catalog.prefix,catalog.inventory);
   token=f.runtime.reserveTemporary(f.source,AndroidHomeStateStore.snapshot(f.service),AndroidNodeChainSession.selection(f.service,f.source),guard,result,capture,catalog);
  }
  AndroidNodeChainSession start(Fixture f)throws Exception{token.start();result.finished();f.drain();check(result.ok,"private prefix failed host startup: "+result.message);return token.session();}
 }
 static void prefixSuccess()throws Exception{
  for(int count:new int[]{2,3,8})try(Fixture f=new Fixture(count)){
   int history=AndroidStartupPolicy.recorded,prepared=AndroidStartupPolicy.prepared,performance=Libbox.performanceStarts;
   Prefix p=new Prefix(f);var session=p.start(f);var server=(CommandServer)get(f.service,"commandServer");var mtu=(AndroidMTUSession)get(f.service,"mtuSession");
   check(session.candidatePrefix==p.capture&&session.candidateCatalog==p.catalog&&p.catalog.session==session,"prefix host replaced original capture/catalog");
   check(p.capture.plan.binds==1&&p.capture.plan.runs==1&&p.capture.plan.server==server,"prefix host skipped exact native bind/run");
   check(p.source.plan.runs==0,"prefix host contacted the unusable old final");
   check(LayeredVpnService.nodeChainCandidatePrefixReady(session)&&!LayeredVpnService.nodeChainReady(session),"private prefix became ordinary service proof");
   var home=AndroidHomeStateStore.snapshot(f.service);
   check(!home.connected&&!"passed".equals(home.pathProof)&&!"connected".equals(home.phase),"private prefix published ordinary Connected Home");
   check(!f.runtime.isConnected()&&f.runtime.captureActive()==null,"private prefix became ordinary runtime authority");
   check(AndroidStartupPolicy.recorded==history&&AndroidStartupPolicy.prepared==prepared&&mtu.activated==null&&Libbox.performanceStarts==performance,"private prefix invoked ordinary Last/MTU/performance");
   reject(session::prove,"private prefix ran complete proof");reject(session::provedExecution,"private prefix lent ordinary execution proof");reject(session::newHopMeasurement,"private prefix lent ordinary telemetry");
   check(Files.readString(session.directory.toPath().resolve("sing-box.json")).equals(p.capture.config),"prefix host staged full saved config");
   check(p.token.drain()&&session.released()&&server.closed&&p.capture.plan.nativeClosed(),"prefix host failed exact native DOWN");f.drain();
   f.connected();var replacement=f.owner();p.token.cancel();check(p.token.drain()&&f.owner()==replacement&&f.runtime.isConnected(),"old prefix drain stopped replacement");f.stop();
  }
 }
 static void prefixDrain()throws Exception{
  try(Fixture f=new Fixture(3)){
   Prefix p=new Prefix(f);var session=p.start(f);var server=(CommandServer)get(f.service,"commandServer");
   p.guard.join=false;check(!p.token.drain()&&!p.capture.plan.cancelled&&p.capture.plan.closes==0&&!server.closed,"prefix retired before candidate drain");
   p.guard.join=true;p.capture.plan.failClose=true;
   try{Method close=LayeredVpnService.class.getDeclaredMethod("closeCoreLocked");close.setAccessible(true);reject(()->close.invoke(f.service),"pending prefix join was discarded");
    check(!server.closed&&!session.released()&&get(f.service,"mtuSession")!=null,"pending prefix join destroyed native graph or MTU");
   }finally{p.capture.plan.failClose=false;}
   check(p.token.drain()&&session.released(),"prefix failed join lost retry authority");f.drain();
  }
 }
 static void prefixReceipt()throws Exception{
  for(String fault:new String[]{"box","receipt"})try(Fixture f=new Fixture(3)){
   Prefix p=new Prefix(f);var session=p.start(f);var server=(CommandServer)get(f.service,"commandServer");
   server.failClose=fault.equals("box");p.capture.plan.missingReceipt=fault.equals("receipt");
   Method close=LayeredVpnService.class.getDeclaredMethod("closeCoreLocked");close.setAccessible(true);
   try{reject(()->close.invoke(f.service),"missing exact native receipt accepted as DOWN");
    check(!session.released()&&get(f.service,"mtuSession")!=null&&get(f.service,"commandServer")==server,"missing native receipt lost original cleanup owners");
   }finally{server.failClose=false;p.capture.plan.missingReceipt=false;}
   check(p.token.drain()&&session.released(),"native close receipt could not retry");f.drain();
  }
 }
 static void prefixSource()throws Exception{
  try(Fixture f=new Fixture(3)){
   Prefix p=new Prefix(f);int created=CommandServer.created;f.source.valid=false;p.token.start();p.result.finished();
   check(!p.result.ok&&created==CommandServer.created,"changed prefix original started native graph");check(p.token.drain(),"changed prefix could not drain pure capture");
  }
  try(Fixture f=new Fixture(3)){
   var a=AndroidNodeChainCapture.compile(f.source);var foreign=new AndroidNodeStore.ChainCapture(3);var catalog=new AndroidNodeCandidateCatalog(foreign,0);var prefix=new AndroidNodeCandidatePrefixCapture(a,0,catalog.inventory);
   reject(()->f.runtime.reserveTemporary(f.source,AndroidHomeStateStore.snapshot(f.service),AndroidNodeChainSession.selection(f.service,f.source),new Guard(),new Result(),prefix,catalog),"foreign catalog bound to prefix purpose");
  }
 }
 public static void main(String[] args)throws Exception{
  String selected=args.length==0?"all":args[0];
  if(selected.equals("all")||selected.equals("success"))prefixSuccess();
  if(selected.equals("all")||selected.equals("drain"))prefixDrain();
  if(selected.equals("all")||selected.equals("receipt"))prefixReceipt();
  if(selected.equals("all")||selected.equals("source"))prefixSource();
  System.out.println("Android actual prefix host checks: "+checks);
 }
}
'''


def main():
    jar=Path(os.environ.get('ANDROID_JSON_JAR','/usr/share/java/com.android.json.jar'))
    if not jar.is_file() or not shutil.which('javac'): raise RuntimeError('JDK17 and Android JSON required')
    with tempfile.TemporaryDirectory(prefix='routervpn-prefix-host-') as directory:
        work=Path(directory);src=work/'src'
        for path,text in base.SOURCES.items():
            if path==base.APP+'AndroidMTUSession.java':
                text=text.replace('candidatePrefixCurrent(AndroidNodeChainSession source){return false;}','candidatePrefixCurrent(AndroidNodeChainSession source){return true;}')
            if path==base.NATIVE+'Libbox.java':
                text=text.replace('public static long routerStartPerformance(CommandServer s)throws Exception{return 0;}','public static int performanceStarts;public static long routerStartPerformance(CommandServer s)throws Exception{performanceStarts++;return 0;}')
            target=src/path;target.parent.mkdir(parents=True,exist_ok=True);target.write_text(text)
        app=src/base.APP
        names=('AndroidHomeStateStore','AndroidConnectionSelection','AndroidNodeChainSession','AndroidNodeChainMTUPlatform','AndroidNodeChainRuntime','LayeredVpnService')
        originals={name:(base.JAVA/(name+'.java')).read_text() for name in names}
        for name,text in originals.items():(app/(name+'.java')).write_text(text)
        marker=' public static void main(String[] args)throws Exception {'
        if base.HARNESS.count(marker)!=1:raise AssertionError('Original host harness seam changed')
        (app/'OrderedRuntimeTest.java').write_text(base.HARNESS.split(marker)[0]+CASES)
        classes=work/'classes';command=['javac','--release','17','-encoding','UTF-8','-proc:none','-cp',str(jar),'-d',str(classes),*map(str,src.rglob('*.java'))]
        subprocess.run(command,check=True,timeout=60)
        cp=os.pathsep.join((str(classes),str(jar)))
        subprocess.run(['java','-cp',cp,'com.eabusham.routervpn.OrderedRuntimeTest'],check=True,timeout=90)
        controls=(
            ('AndroidNodeChainSession','candidatePrefix==null&&(execution == null ? capture.plan.healthy() : execution.healthy())','candidatePrefix!=null|| (execution == null ? capture.plan.healthy() : execution.healthy())','success','private prefix lent ordinary execution proof'),
            ('LayeredVpnService','capturedChain.prepareCandidates();','capturedChain.prove();','success','private prefix failed host startup:'),
            ('AndroidNodeChainRuntime','// Internal completion lends only candidate authority.','AndroidHomeStateStore.connectedNodeChain(context,home); // Internal completion lends only candidate authority.','success','private prefix published ordinary Connected Home'),
            ('LayeredVpnService','chain.closePlan();chain.requireNativeBindingDrain();','chain.requireNativeBindingDrain();','drain','pending prefix join destroyed native graph or MTU'),
            ('AndroidNodeChainSession','if(candidatePrefix!=null&&(server==null?owner!=null||!proofClosed:!candidatePrefix.plan.nativeClosed()))','if(false)','receipt','missing exact native receipt accepted as DOWN'),
        )
        for index,(name,before,after,family,witness) in enumerate(controls):
            if originals[name].count(before)!=1:raise AssertionError('Exact prefix host control seam changed: '+before)
            out=work/('negative-'+str(index));shutil.copytree(classes,out);mutation=work/('mutant-'+str(index))/(name+'.java');mutation.parent.mkdir();mutation.write_text(originals[name].replace(before,after));cp=os.pathsep.join((str(out),str(jar)))
            subprocess.run(['javac','--release','17','-encoding','UTF-8','-proc:none','-cp',cp,'-d',str(out),str(mutation)],check=True,timeout=60)
            result=subprocess.run(['java','-cp',cp,'com.eabusham.routervpn.OrderedRuntimeTest',family],text=True,capture_output=True,timeout=90)
            if result.returncode==0 or witness not in result.stderr:raise AssertionError('Prefix host control missed '+witness+'\n'+result.stdout+'\n'+result.stderr)
            print('Android prefix host rejected: '+witness,flush=True)


if __name__=='__main__':main()
