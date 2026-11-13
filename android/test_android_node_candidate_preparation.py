#!/usr/bin/env python3
"""Run the real ordered host under an idle temporary reservation.

Runtime, Session, Home, and LayeredVpnService are shipping source. OS/native
handles and the not-yet-wired candidate guard are explicit fixture boundaries.
This proves host ownership, not native network traffic or a finished UI flow.
"""
from pathlib import Path
import importlib.util
import os
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('temporary_ordered_host', ROOT / 'android/test_android_node_chain_runtime.py')
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)

CASES = r'''
 static final class Guard implements AndroidNodeChainRuntime.TemporaryGuard {
  volatile boolean valid=true,join=true;volatile int checks,cancels,drains;
  public void requireCurrent(){checks++;if(!valid)throw new IllegalStateException("captured physical cohort changed");}
  public void cancel(){cancels++;}public boolean drain(){drains++;return join;}
 }
 static AndroidNodeChainRuntime.Temporary reserve(Fixture f,Guard guard,Result result)throws Exception {
  var idle=AndroidHomeStateStore.snapshot(f.service);
  return f.runtime.reserveTemporary(f.source,idle,AndroidNodeChainSession.selection(f.service,f.source),guard,result);
 }
 static AndroidNodeChainRuntime.Temporary prepared(Fixture f,Guard guard,Result result)throws Exception {
  var token=reserve(f,guard,result);token.start();result.finished();f.drain();
  check(result.ok,"temporary full saved graph did not prove: "+result.message);return token;
 }
 static void temporarySuccess()throws Exception {
  for(int count:new int[]{2,3,4,8})try(Fixture f=new Fixture(count)){
   int history=AndroidStartupPolicy.recorded;Guard guard=new Guard();Result result=new Result();var token=prepared(f,guard,result);
   var session=token.session();var plan=session.capture.plan;var server=(CommandServer)get(f.service,"commandServer");
   check(session==f.owner()&&session.source==f.source&&plan.count==count&&plan.runs==1&&plan.server==server,"temporary preparation substituted a pair or another original graph");
   check(AndroidStartupPolicy.recorded==history,"temporary preparation overwrote ordered Last history");
   check(Libbox.mtuPlan==plan&&Libbox.mtuServer==server,"temporary preparation skipped actual original MTU activation");
   check(!f.runtime.isConnected()&&f.runtime.captureActive()==null&&f.runtime.activeSources().isEmpty(),"temporary preparation leaked into ordinary connected authority");
   reject(f.runtime::captureRestore,"temporary preparation became Speed Lab restore authority");
   check(!f.runtime.disconnectAndDrainCaptured(session.home.sessionId)&&!plan.cancelled,"captured disconnect bypassed the temporary measurement drain");
   guard.join=false;int closes=plan.closes;
   check(!f.runtime.stopAndProve()&&plan.closes==closes&&!plan.cancelled&&!session.released(),"temporary graph retired before its held candidate drain");
   check(guard.cancels>0&&guard.drains>0&&f.runtime.isActiveOrTransitioning(),"failed candidate drain lost its temporary reservation");
   reject(token::session,"cancelled temporary preparation still authorized candidates");
   Result replacement=new Result();f.runtime.connect(f.source,replacement);replacement.finished();check(!replacement.ok,"held candidate drain admitted a replacement graph");
   guard.join=true;check(token.drain(),"temporary measurement drain could not finish its exact graph");f.drain();
   check(session.released()&&server.closed&&!f.runtime.isActiveOrTransitioning(),"temporary cleanup dropped a native handle or reservation");
   check(!AndroidHomeStateStore.snapshot(f.service).connected,"temporary cleanup left Home connected");
   f.connected();var newer=f.owner();int cancelled=guard.cancels,drained=guard.drains;
   token.cancel();check(token.drain()&&f.runtime.isConnected()&&f.owner()==newer&&!newer.capture.plan.cancelled,"stale temporary cleanup stopped a replacement graph");
   check(guard.cancels==cancelled&&guard.drains==drained,"stale temporary cleanup reclaimed an old external lease");
   f.stop();
  }
 }
 static void temporaryReservation()throws Exception {
  try(Fixture f=new Fixture(3)){
   Guard guard=new Guard();Result result=new Result();var idle=AndroidHomeStateStore.snapshot(f.service);int created=CommandServer.created;
   var token=reserve(f,guard,result);
   check(f.runtime.isActiveOrTransitioning()&&f.owner()==null&&CommandServer.created==created,"reservation started a native graph before its handle was retained");
   var still=AndroidHomeStateStore.snapshot(f.service);check(idle.sessionId.equals(still.sessionId)&&idle.pathGeneration==still.pathGeneration&&idle.phase.equals(still.phase),"reservation changed the original idle Home receipt");
   reject(()->reserve(f,new Guard(),new Result()),"two temporary reservations shared one runtime");
   guard.join=false;token.cancel();check(!token.drain()&&f.runtime.isActiveOrTransitioning(),"unstarted failed drain lost the original reservation");
   guard.join=true;check(token.drain()&&!f.runtime.isActiveOrTransitioning()&&CommandServer.created==created,"unstarted cancellation created or retained native work");
   reject(token::start,"cancelled temporary reservation started later");
   f.source.execution="server";reject(()->reserve(f,new Guard(),new Result()),"temporary preparation admitted saved Server execution");f.source.execution="local";
   f.connected();reject(()->reserve(f,new Guard(),new Result()),"temporary preparation interrupted an active connection");f.stop();
  }
 }
 static void temporaryInvalidation()throws Exception {
  for(String family:new String[]{"source","selection","network"})try(Fixture f=new Fixture(3)){
   Guard guard=new Guard();Result result=new Result();int history=AndroidStartupPolicy.recorded;var token=reserve(f,guard,result);
   if(family.equals("source"))f.source.valid=false;
   if(family.equals("selection"))f.service.getSharedPreferences("router-vpn-unified",0).edit().putBoolean("multihop_on",true).apply();
   if(family.equals("network"))RouterNodeChain.configured=plan->plan.afterRun=()->guard.valid=false;
   token.start();result.finished();f.drain();
   check(!result.ok,"stale temporary capture reached success: "+family);
   check(AndroidStartupPolicy.recorded==history,"failed temporary proof persisted Last history");
   check(token.drain()&&!f.runtime.isActiveOrTransitioning(),"failed temporary preparation could not drain: "+family);
  }
 }
 static void temporaryNetwork()throws Exception {
  try(Fixture f=new Fixture(3)){
   Guard guard=new Guard();Result result=new Result();var token=prepared(f,guard,result);var session=token.session();var plan=session.capture.plan;
   guard.join=false;guard.valid=false;int closes=plan.closes;
   try{
    f.runtime.networkChanged(session.home);
    await(()->guard.drains>0||plan.cancelled,"network cancellation reached neither its captured guard nor native owner");
    check(guard.cancels>0&&guard.drains>0&&!plan.cancelled&&plan.closes==closes&&!session.released(),"network change invalidated native graph before candidate callbacks joined");
    reject(token::session,"changed physical cohort still authorized a temporary candidate");
    check(f.runtime.isActiveOrTransitioning(),"network change dropped retryable temporary cleanup");
   }finally{guard.join=true;token.drain();}
   check(token.drain()&&session.released(),"network-change cleanup could not retry its exact owner");f.drain();
   f.connected();var newer=f.owner();f.runtime.networkChanged(session.home);check(f.owner()==newer&&f.runtime.isConnected(),"old network event stopped a replacement graph");f.stop();
  }
 }
 static void temporaryDisconnect()throws Exception {
  for(boolean closing:new boolean[]{false,true})try(Fixture f=new Fixture(3)){
   Guard guard=new Guard();Result result=new Result();var token=prepared(f,guard,result);var session=token.session();var plan=session.capture.plan;guard.join=false;
   if(closing){f.runtime.close();((ExecutorService)get(f.runtime,"executor")).submit(()->{}).get(5,TimeUnit.SECONDS);}
   else{Result stopped=new Result();f.runtime.disconnect(stopped);stopped.finished();check(!stopped.ok,"Disconnect falsely acknowledged held candidate cleanup");}
   check(!plan.cancelled&&!session.released()&&f.runtime.isActiveOrTransitioning(),"Disconnect or close bypassed temporary candidate cleanup");
   guard.join=true;check(token.drain()&&session.released(),"Disconnect or close lost the retained temporary retry handle");f.drain();
  }
 }
 static void temporaryNativeRetry()throws Exception {
  try(Fixture f=new Fixture(3)){
   Guard guard=new Guard();Result result=new Result();var token=prepared(f,guard,result);var session=token.session();var server=(CommandServer)get(f.service,"commandServer");server.failClose=true;
   check(!token.drain()&&!session.released()&&f.runtime.isActiveOrTransitioning(),"failed native cleanup discarded the temporary retry handle");f.drain();
   Result replacement=new Result();f.runtime.connect(f.source,replacement);replacement.finished();check(!replacement.ok,"failed temporary native join admitted a replacement");
   server.failClose=false;check(token.drain()&&session.released()&&!f.runtime.isActiveOrTransitioning(),"temporary retry did not join its exact native owner");f.drain();
  }
 }
 static void temporaryServiceTeardown()throws Exception {
  for(String event:new String[]{"stop","revoke","destroy","owned-stop"})try(Fixture f=new Fixture(3)){
   Guard guard=new Guard();Result result=new Result();var token=prepared(f,guard,result);var session=token.session();var plan=session.capture.plan;var server=(CommandServer)get(f.service,"commandServer");
   guard.join=false;int closes=plan.closes;
   if(event.equals("revoke"))f.service.onRevoke();
   else if(event.equals("destroy"))f.service.onDestroy();
   else if(event.equals("owned-stop"))f.nativeOwner.stopNodeChain(session.sessionId);
   else f.service.onStartCommand(new Intent().setAction(LayeredVpnService.ACTION_STOP),0,1);
   f.drain();await(()->guard.drains>0||session.released()||server.closed,"Service teardown bypassed original candidate join: "+event);
   check(guard.cancels>0&&guard.drains>0&&plan.closes==closes&&!server.closed&&!session.released(),"Service teardown bypassed original candidate join: "+event);
   check(f.runtime.isActiveOrTransitioning(),"Service teardown dropped the original temporary cleanup authority: "+event);
   guard.join=true;check(token.drain()&&session.released()&&server.closed&&!f.runtime.isActiveOrTransitioning(),"Service teardown lost exact temporary retry authority: "+event);
  }
 }
 public static void main(String[] args)throws Exception {
  String family=args.length==0?"all":args[0];
  if(family.equals("all")||family.equals("success"))temporarySuccess();
  if(family.equals("all")||family.equals("reservation"))temporaryReservation();
  if(family.equals("all")||family.equals("invalidation"))temporaryInvalidation();
  if(family.equals("all")||family.equals("network"))temporaryNetwork();
  if(family.equals("all")||family.equals("disconnect"))temporaryDisconnect();
  if(family.equals("all")||family.equals("retry"))temporaryNativeRetry();
  if(family.equals("all")||family.equals("service"))temporaryServiceTeardown();
  System.out.println("Android temporary ordered host: "+checks+" executable checks passed; native/OS and candidate guard boundaries doubled.");
 }
}'''


def main():
    jar = Path(os.environ.get('ANDROID_JSON_JAR', '/usr/share/java/com.android.json.jar'))
    if not jar.is_file() or not shutil.which('javac'):
        raise RuntimeError('Actual JDK17 and Android JSON library required')
    with tempfile.TemporaryDirectory(prefix='routervpn-temporary-ordered-') as directory:
        work = Path(directory)
        src = work / 'src'
        for path, text in base.SOURCES.items():
            if path == base.APP + 'AndroidNodeStore.java':
                # This capture boundary must vary execution at runtime; a final
                # constant would let javac erase the shipping Local admission.
                if text.count('final String execution="local";') != 1:
                    raise AssertionError('Original execution capture boundary changed')
                text = text.replace('final String execution="local";', 'String execution="local";')
            target = src / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(text)
        app = src / base.APP
        names = ('AndroidHomeStateStore', 'AndroidConnectionSelection', 'AndroidNodeChainSession', 'AndroidNodeChainMTUPlatform', 'AndroidNodeChainRuntime', 'LayeredVpnService')
        for name in names:
            (app / (name + '.java')).write_text((base.JAVA / (name + '.java')).read_text())
        marker = ' public static void main(String[] args)throws Exception {'
        if base.HARNESS.count(marker) != 1:
            raise AssertionError('Original native host fixture main boundary changed')
        (app / 'OrderedRuntimeTest.java').write_text(base.HARNESS.split(marker)[0] + CASES)
        classes = work / 'classes'
        subprocess.run(['javac', '--release', '17', '-encoding', 'UTF-8', '-proc:none', '-cp', str(jar), '-d', str(classes), *map(str, src.rglob('*.java'))], check=True, timeout=60)
        subprocess.run(['java', '-cp', os.pathsep.join((str(classes), str(jar))), 'com.eabusham.routervpn.OrderedRuntimeTest'], check=True, timeout=90)
        original = (base.JAVA / 'AndroidNodeChainRuntime.java').read_text()
        controls = (
            ('selectedOperation,false,null,prefix,catalog,new Callback()', 'selectedOperation,true,null,prefix,catalog,new Callback()', 'success', 'temporary preparation overwrote ordered Last history'),
            ('if(!guard.drain())return false;', 'guard.drain();', 'success', 'temporary graph retired before its held candidate drain'),
            ('public void validate() throws Exception { requireCurrent(); }', 'public void validate() throws Exception {}', 'invalidation', 'stale temporary capture reached success: network'),
            ('if(preparation!=null) {\n            preparation.cancel();', 'if(false) {\n            preparation.cancel();', 'network', 'network change invalidated native graph before candidate callbacks joined'),
            ('if (temporary != null || homeSession == null', 'if (homeSession == null', 'success', 'captured disconnect bypassed the temporary measurement drain'),
            ('if(temporary!=this||operation!=selectedOperation)return true; // Already joined; never touch a replacement.', 'if(false)return true; // Already joined; never touch a replacement.', 'success', 'stale temporary cleanup reclaimed an old external lease'),
            ('cancelled=true;\n                if(temporary!=this||operation!=selectedOperation)return;', 'cancelled=true;', 'success', 'stale temporary cleanup stopped a replacement graph'),
            ('if(!"local".equals(source.execution))', 'if(false)', 'reservation', 'temporary preparation admitted saved Server execution'),
            ('session.bindTemporaryDrain(preparation::drainMeasurements);', 'session.bindTemporaryDrain(()->true);', 'service', 'Service teardown bypassed original candidate join'),
        )
        for number, (before, after, family, witness) in enumerate(controls):
            if original.count(before) != 1:
                raise AssertionError('Temporary owner negative control lost exact seam: ' + before)
            out = work / ('negative-' + str(number))
            shutil.copytree(classes, out)
            mutation = work / ('mutant-' + str(number)) / 'AndroidNodeChainRuntime.java'
            mutation.parent.mkdir()
            mutation.write_text(original.replace(before, after))
            cp = os.pathsep.join((str(out), str(jar)))
            subprocess.run(['javac', '--release', '17', '-encoding', 'UTF-8', '-proc:none', '-cp', cp, '-d', str(out), str(mutation)], check=True, timeout=60)
            result = subprocess.run(['java', '-cp', cp, 'com.eabusham.routervpn.OrderedRuntimeTest', family], capture_output=True, text=True, timeout=60)
            if result.returncode == 0 or witness not in result.stderr:
                raise AssertionError('Temporary owner negative control missed its defect: ' + family + '\n' + result.stdout + '\n' + result.stderr)
            print('Android temporary ordered host rejected: ' + family + '/' + str(number), flush=True)
        service = (base.JAVA / 'LayeredVpnService.java').read_text()
        seam = '            chain.requireTemporaryDrain();'
        if service.count(seam) != 1:
            raise AssertionError('Original service temporary drain boundary changed')
        out = work / 'negative-service'
        shutil.copytree(classes, out)
        mutation = work / 'mutant-service' / 'LayeredVpnService.java'
        mutation.parent.mkdir()
        mutation.write_text(service.replace(seam, ''))
        cp = os.pathsep.join((str(out), str(jar)))
        subprocess.run(['javac', '--release', '17', '-encoding', 'UTF-8', '-proc:none', '-cp', cp, '-d', str(out), str(mutation)], check=True, timeout=60)
        result = subprocess.run(['java', '-cp', cp, 'com.eabusham.routervpn.OrderedRuntimeTest', 'service'], capture_output=True, text=True, timeout=60)
        if result.returncode == 0 or 'Service teardown bypassed original candidate join' not in result.stderr:
            raise AssertionError('Service drain negative control missed its defect\n' + result.stdout + '\n' + result.stderr)
        print('Android temporary ordered host rejected: service/core-drain', flush=True)


if __name__ == '__main__':
    main()
