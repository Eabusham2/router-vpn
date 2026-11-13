#!/usr/bin/env python3
"""Execute the shipping Android MTU adapter for a retained ordered native graph.

The real MTUSession and measurement gate run unchanged. OS readback and native
handles are doubled; the complete source/native graph have independent gates.
"""
from pathlib import Path
import importlib.util
import os
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
JAVA = ROOT / 'android/app/src/main/java/com/eabusham/routervpn'
spec = importlib.util.spec_from_file_location('ordered_mtu_boundaries', ROOT / 'android/test_android_mtu_session.py')
M = importlib.util.module_from_spec(spec)
spec.loader.exec_module(M)
SOURCES = dict(M.STUBS)
SOURCES['com/eabusham/routervpn/AndroidNodeChainSession.java'] = r'''package com.eabusham.routervpn;
final class AndroidNodeChainSession {
 final io.nekohasekai.libbox.CommandServer server=new io.nekohasekai.libbox.CommandServer();
 volatile boolean valid=true;boolean automatic=true,restoringExecution;int calls;io.nekohasekai.libbox.RouterMTUPlatform platform;
 void requireCurrent(){if(!valid)throw new IllegalStateException("original ordered source retired");}boolean healthy(){return valid;}
 io.nekohasekai.libbox.RouterMTU newMTU(io.nekohasekai.libbox.RouterMTUPlatform owner)throws Exception {
  requireCurrent();calls++;platform=owner;var result=io.nekohasekai.libbox.Libbox.newRouterMTU(server,owner,"original complete ordered config","native all-member capacity");result.automatic=automatic;return result;
 }
}'''
HARNESS = r'''package com.eabusham.routervpn;
import io.nekohasekai.libbox.*;import java.util.concurrent.*;import java.util.concurrent.atomic.*;import java.lang.reflect.*;import org.json.*;
public final class OrderedMTUTest {
 static int checks;interface Action{void run()throws Exception;}static void check(boolean value,String message){checks++;if(!value)throw new AssertionError(message);}static void reject(Action call,String message)throws Exception{try{call.run();}catch(Exception expected){checks++;return;}throw new AssertionError(message);}
 static Object controller(AndroidMTUSession owner)throws Exception{Field field=AndroidMTUSession.class.getDeclaredField("controller");field.setAccessible(true);return field.get(owner);}
 static void reset(){Libbox.afterCreate=null;Libbox.latest=null;}
 static void success()throws Exception {
  reset();Main.Fixture f=new Main.Fixture();f.establish();AndroidNodeChainSession chain=new AndroidNodeChainSession();f.owner.activateNodeChain(chain);RouterMTU nativeOwner=Libbox.latest;
  check(nativeOwner!=null&&nativeOwner.starts==1&&chain.platform==f.owner&&chain.calls==1,"ordered Auto MTU lost its original platform/native owner");
  f.owner.activateNodeChain(chain);check(chain.calls==1&&nativeOwner.starts==1,"ordered Auto constructed a second optimizer");
  Object hold=AndroidMTUMeasurementGate.acquire();f.owner.drainForMeasurement();check(!nativeOwner.running()&&nativeOwner.cancels==1,"ordered measurement did not join before temporary traffic");
  reject(()->f.owner.request("start",f.owner.identity,"a".repeat(32)),"Retest bypassed the held ordered path");AndroidMTUMeasurementGate.release(hold);
  f.owner.request("start",f.owner.identity,"b".repeat(32));f.owner.request("cancel",f.owner.identity,"b".repeat(32));check(nativeOwner.starts==2&&nativeOwner.cancels==2,"ordered Retest/Cancel replaced its original optimizer");
  f.owner.close();check(nativeOwner.closes==1&&controller(f.owner)==null,"ordered MTU did not acknowledge its native join");
 }
 static void restored()throws Exception {
  reset();Main.Fixture f=new Main.Fixture();f.establish(1360);AndroidNodeChainSession chain=new AndroidNodeChainSession();chain.restoringExecution=true;f.owner.activateNodeChain(chain);RouterMTU nativeOwner=Libbox.latest;
  check(nativeOwner!=null&&nativeOwner.starts==0&&nativeOwner.attempts==0,"temporary restore replayed automatic MTU search");
  f.owner.activateNodeChain(chain);f.owner.resumeAfterResponse();check(nativeOwner.starts==0,"restored observation resumed deferred Auto MTU");
  check(f.owner.captureMTU().getMTU()==1360,"restored effective MTU changed before explicit Retest");
  f.owner.request("start",f.owner.identity,"d".repeat(32));check(nativeOwner.starts==1,"restored execution could not perform explicit user Retest");f.owner.request("cancel",f.owner.identity,"d".repeat(32));f.owner.close();check(nativeOwner.closes==1,"restored MTU owner did not join exact native close");
 }
 static void policies()throws Exception {
  for(int capacity:new int[]{1280,1408,2000,9000}){
   reset();Main.Fixture f=new Main.Fixture();f.establish(capacity);AndroidNodeChainSession chain=new AndroidNodeChainSession();chain.automatic=false;f.owner.activateNodeChain(chain);RouterMTU nativeOwner=Libbox.latest;
   check(nativeOwner!=null&&nativeOwner.attempts==0,"fixed inherited ordered capacity attempted Auto MTU");
   JSONObject status=new JSONObject(f.owner.request("status",f.owner.identity,""));check(!status.getBoolean("optimization_allowed")&&status.getString("source").equals("configured-unmeasured"),"configured ordered capacity was reported as measured/optimizable");
   reject(()->f.owner.request("start",f.owner.identity,"a".repeat(32)),"fixed ordered native authority allowed Retest");f.owner.close();
  }
  for(int capacity:new int[]{1280,2000,9000}){
   reset();Main.Fixture f=new Main.Fixture();f.establish(capacity);AndroidNodeChainSession chain=new AndroidNodeChainSession();chain.valid=false;f.owner.activateNodeChain(chain);
   check(chain.calls==0&&Libbox.latest==null,"unproved original source constructed ordered MTU");check(f.aborts==(capacity>1500?1:0),"unverified large ordered capacity did not abort its native path");f.owner.close();
  }
 }
 static void constructorRetirement()throws Exception {
  reset();Main.Fixture f=new Main.Fixture();f.establish();AndroidNodeChainSession chain=new AndroidNodeChainSession();Libbox.afterCreate=value->chain.valid=false;f.owner.activateNodeChain(chain);RouterMTU created=Libbox.latest;
  check(created!=null&&created.starts==0,"retired ordered source started its returned MTU controller");check(controller(f.owner)==created,"retired constructor lost its sole native cleanup handle");f.owner.close();check(created.closes==1,"retired constructor native owner was not joined");
  reset();Main.Fixture blocked=new Main.Fixture();blocked.establish();AndroidNodeChainSession original=new AndroidNodeChainSession();CountDownLatch entered=new CountDownLatch(1),release=new CountDownLatch(1);AtomicReference<Throwable> failure=new AtomicReference<>();
  Libbox.afterCreate=value->{entered.countDown();if(!release.await(3,TimeUnit.SECONDS))throw new IllegalStateException("native constructor fixture did not release");};
  Thread constructor=new Thread(()->blocked.owner.activateNodeChain(original));constructor.start();check(entered.await(2,TimeUnit.SECONDS),"ordered native constructor was not in flight");
  Thread close=new Thread(()->{try{blocked.owner.close();}catch(Throwable error){failure.set(error);}});close.start();long end=System.nanoTime()+TimeUnit.SECONDS.toNanos(2);while(blocked.owner.proofOwnerCurrent()&&System.nanoTime()<end)Thread.sleep(2);
  check(!blocked.owner.proofOwnerCurrent(),"native close did not revoke the in-flight ordered constructor");release.countDown();constructor.join(3000);close.join(3000);check(!constructor.isAlive()&&!close.isAlive()&&failure.get()==null,"ordered constructor/close deadlocked");
  check(Libbox.latest.starts==0&&Libbox.latest.closes==1&&controller(blocked.owner)==null,"late ordered constructor escaped native close or lost join ownership");reset();
 }
 static void retry()throws Exception {
  reset();Main.Fixture f=new Main.Fixture();f.establish();f.owner.activateNodeChain(new AndroidNodeChainSession());RouterMTU nativeOwner=Libbox.latest;nativeOwner.closeFailures=1;
  reject(f.owner::close,"failed ordered MTU drain reported successful close");check(controller(f.owner)==nativeOwner,"failed ordered MTU join discarded its exact owner");f.owner.close();check(nativeOwner.closes==2&&controller(f.owner)==null,"ordered MTU retry did not join its original owner");
 }
 static void observation()throws Exception {
  Main.Fixture f=new Main.Fixture();f.establish();Long original=f.owner.proofObservationToken();check(original!=null&&f.owner.proofOwnerCurrent(),"stable MTU has no proof observation token");
  f.owner.beginMTUChange(f.owner.captureMTU());check(f.owner.proofObservationToken()==null&&f.owner.proofOwnerCurrent(),"owned TUN mutation did not defer proof observation");
  f.owner.endMTUChange();Long next=f.owner.proofObservationToken();check(next!=null&&!next.equals(original),"MTU mutation revived an old proof observation token");
  f.owner.networkChanged();check(f.owner.proofObservationToken()==null&&!f.owner.proofOwnerCurrent(),"retired MTU could defer ordered proof forever");f.owner.close();
 }
 static void temporaryCandidates()throws Exception {
  for(boolean automatic:new boolean[]{true,false}){
   reset();Main.Fixture f=new Main.Fixture();f.establish(1408);AndroidNodeChainSession chain=new AndroidNodeChainSession();chain.automatic=automatic;Object lease=AndroidMTUMeasurementGate.acquire();
   try{
    reject(()->f.owner.prepareNodeCandidates(chain,new Object()),"temporary candidate MTU admitted a foreign lease");
    f.owner.prepareNodeCandidates(chain,lease);RouterMTU nativeOwner=Libbox.latest;
    check(nativeOwner!=null&&controller(f.owner)==nativeOwner&&chain.calls==1&&chain.platform==f.owner,"temporary candidate skipped its actual original MTU controller");
    check(nativeOwner.starts==0&&nativeOwner.attempts==0&&f.owner.captureMTU().getMTU()==1408,"temporary candidate changed or invented its configured MTU proof");
    check(AndroidMTUMeasurementGate.owns(lease),"MTU preparation released the outer candidate hold");
    f.owner.close();check(nativeOwner.closes==1&&AndroidMTUMeasurementGate.owns(lease),"native MTU cleanup released the outer graph hold");
   }finally{AndroidMTUMeasurementGate.release(lease);}
  }
  reset();Main.Fixture f=new Main.Fixture();f.establish();AndroidNodeChainSession chain=new AndroidNodeChainSession();Object lease=AndroidMTUMeasurementGate.acquire();
  try{
   chain.valid=false;f.owner.activateNodeChain(chain);chain.valid=true;
   check(controller(f.owner)==null,"failed ordered MTU construction fixture unexpectedly created a controller");
   reject(()->f.owner.prepareNodeCandidates(chain,lease),"temporary candidate bypassed failed native MTU construction");f.owner.close();
  }finally{AndroidMTUMeasurementGate.release(lease);}
 }
 public static void main(String[] args)throws Exception{String family=args.length==0?"all":args[0];if(family.equals("all")||family.equals("success"))success();if(family.equals("all")||family.equals("restored"))restored();if(family.equals("all")||family.equals("policy"))policies();if(family.equals("all")||family.equals("constructor"))constructorRetirement();if(family.equals("all")||family.equals("retry"))retry();if(family.equals("all")||family.equals("observation"))observation();if(family.equals("all")||family.equals("temporary"))temporaryCandidates();reset();System.out.println("Android ordered MTU adapter: "+checks+" executable checks passed; OS/native handles doubled.");}
}'''


def main():
    jar = Path(os.environ.get('ANDROID_JSON_JAR', '/usr/share/java/com.android.json.jar'))
    if not jar.is_file() or not shutil.which('javac'):
        raise RuntimeError('A JDK and actual Android JSON implementation are required')
    with tempfile.TemporaryDirectory(prefix='routervpn-ordered-mtu-') as directory:
        work = Path(directory)
        src = work / 'src'
        for path, text in SOURCES.items():
            target = src / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(text)
        app = src / 'com/eabusham/routervpn'
        for name in ('AndroidMTUSession', 'AndroidMTUMeasurementGate'):
            shutil.copyfile(JAVA / (name + '.java'), app / (name + '.java'))
        (app / 'Main.java').write_text(M.HARNESS)
        (app / 'OrderedMTUTest.java').write_text(HARNESS)
        classes = work / 'classes'
        subprocess.run(['javac', '--release', '17', '-encoding', 'UTF-8', '-proc:none', '-cp', str(jar), '-d', str(classes), *map(str, src.rglob('*.java'))], check=True, timeout=60)
        subprocess.run(['java', '-cp', os.pathsep.join((str(classes), str(jar))), 'com.eabusham.routervpn.OrderedMTUTest'], check=True, timeout=40)
        original = (app / 'AndroidMTUSession.java').read_text()
        start = original.index('    void activateNodeChain(')
        end = original.index('    void activateTor(', start)
        method = original[start:end]
        controls = (
            (method.replace('automaticDeferred = !chain.restoringExecution;', 'automaticDeferred = true;'), 'restored', 'temporary restore replayed automatic MTU search'),
            (method.replace('                chain.requireCurrent();\n                if (created.autoRequested()', '                if (created.autoRequested()'), 'constructor', 'retired ordered source started its returned MTU controller'),
            (method.replace('                controller = created;', ''), 'constructor', 'retired constructor lost its sole native cleanup handle'),
            (method.replace('if (created.autoRequested() == false)', 'if (false)'), 'policy', 'fixed inherited ordered capacity attempted Auto MTU'),
            (method.replace('if (!closed && !invalid && large) abortMTU', 'if (false) abortMTU'), 'policy', 'unverified large ordered capacity did not abort its native path'),
        )
        mutants = [(original[:start] + changed + original[end:], family, witness) for changed, family, witness in controls]
        mutants.append((original.replace('proofGeneration++;', ''), 'observation', 'MTU mutation revived an old proof observation token'))
        mutants.append((original.replace('if(!AndroidMTUMeasurementGate.owns(lease))', 'if(false)'), 'temporary', 'temporary candidate MTU admitted a foreign lease'))
        mutants.append((original.replace('if(closed||invalid||controller==null)', 'if(closed||invalid)'), 'temporary', 'temporary candidate bypassed failed native MTU construction'))
        for number, (changed, family, witness) in enumerate(mutants):
            if changed == original:
                raise AssertionError('Ordered MTU mutation lost its source seam: ' + family)
            out = work / ('negative-' + str(number))
            shutil.copytree(classes, out)
            target = work / ('mutant-' + str(number)) / 'AndroidMTUSession.java'
            target.parent.mkdir()
            target.write_text(changed)
            cp = os.pathsep.join((str(out), str(jar)))
            subprocess.run(['javac', '--release', '17', '-encoding', 'UTF-8', '-proc:none', '-cp', cp, '-d', str(out), str(target)], check=True, timeout=60)
            result = subprocess.run(['java', '-cp', cp, 'com.eabusham.routervpn.OrderedMTUTest', family], capture_output=True, text=True, timeout=40)
            if result.returncode == 0 or witness not in result.stderr:
                raise AssertionError('Ordered MTU causal control missed its defect: ' + family + '\n' + result.stderr)
            print('Android ordered MTU causal control rejected: ' + family)


if __name__ == '__main__':
    main()
