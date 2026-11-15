#!/usr/bin/env python3
"""Execute the original Android generic ordered owner with an imported SS middle.

Pure-source compilation is separately checked by ordered-openvpn using real Go.
Native generation/capacity is an explicit rejecting boundary here; this verifies
host refusal, original-owner cleanup and restoration, not native packet traffic.
"""
from pathlib import Path
import os
import subprocess
import tempfile
import test_android_node_chain_runtime as R
ROOT=R.ROOT
SOURCES=dict(R.SOURCES)
a='selected.add(i==count-1?finalMode:prefixMode);'
b='selected.add(i==count-1?finalMode:i==count-2?"shadowsocks":prefixMode);'
assert SOURCES[R.APP+'AndroidNodeStore.java'].count(a)==1
SOURCES[R.APP+'AndroidNodeStore.java']=SOURCES[R.APP+'AndroidNodeStore.java'].replace(a,b,1)
HARNESS=R.HARNESS[:R.HARNESS.index(' public static void main(String[] args)throws Exception {')]+r'''
 static void importedSS(int count)throws Exception {
  for(String mode:List.of("wg","awg2-fast","awg2-strong"))try(Fixture f=new Fixture(count,mode,"shadowsocks")){
   f.connected();AndroidNodeChainSession original=f.owner();RouterNodeChain plan=original.capture.plan;
   java.util.ArrayList<String> expected=new java.util.ArrayList<>();for(int i=0;i<count-2;i++)expected.add(mode);expected.add("shadowsocks");expected.add("shadowsocks");
   check(f.runtime.activeModes().equals(expected),"imported SS host reordered original modes");
   check(plan.runs==1&&Libbox.mtuPlan==plan&&Libbox.mtuServer==plan.server,"imported SS proof/MTU used another original owner");
   var restore=f.runtime.captureRestore();plan.failCloses=Integer.MAX_VALUE;
   check(!f.runtime.stopAndProve()&&!original.released()&&original.directory.exists(),"imported SS failed shared join discarded original source");
   check(get(f.service,"nodeChainSession")==original&&get(f.service,"commandServer")==plan.server,"imported SS failed join lost exact native cleanup handles");
   reject(original::finishCleanup,"imported SS unjoined source published cleanup");
   plan.failCloses=0;f.stop();check(original.released(),"imported SS original owner did not retire after join");
   Result replay=new Result();f.runtime.restore(restore,AndroidHomeStateStore.snapshot(f.service),replay);replay.finished();
   check(replay.ok&&f.runtime.restoredMatches(restore),"imported SS exact original source did not restore");
   AndroidNodeChainSession replacement=f.owner();
   check(replacement!=original&&replacement.source==original.source&&replacement.capture.plan!=plan&&replacement.capture.plan.runs==1,"imported SS restore reused old native generation");
   original.cancel();check(f.runtime.isConnected()&&f.owner()==replacement,"imported SS old cleanup mutated replacement connection");f.stop();
  }
  try(Fixture f=new Fixture(3)){
   RouterNodeChain.configured=plan->plan.afterRun=()->plan.valid=false;
   Result failed=f.connect();check(!failed.ok&&!f.runtime.isConnected(),"imported SS native proof/source refusal reached Connected");
   check(RouterNodeChain.latest.closes>0,"imported SS failed native proof lost original cleanup");
  }
  try(Fixture f=new Fixture(3)){
   f.connected();AndroidNodeChainSession original=f.owner();f.source.valid=false;
   reject(original::requireCurrent,"imported SS changed source retained host authority");f.stop();
  }
 }
 public static void main(String[] args)throws Exception {int count=args.length==0?3:Integer.parseInt(args[0]);if(count!=3&&count!=4&&count!=8)throw new AssertionError("uncaptured imported SS member count");importedSS(count);System.out.println("Android imported SS middle owner count="+count+": "+checks+" checks PASS; native generation/OS boundaries doubled");}
}'''

def main():
    jar=Path(os.environ.get('ANDROID_JSON_JAR','/usr/share/java/com.android.json.jar'))
    with tempfile.TemporaryDirectory(prefix='android-imported-ss-middle-host-') as folder:
        w=Path(folder);src=w/'src';classes=w/'classes'
        for name,text in SOURCES.items():
            p=src/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_text(text)
        names=('AndroidHomeStateStore','AndroidConnectionSelection','AndroidNodeChainSession','AndroidNodeChainMTUPlatform','AndroidNodeChainRuntime','LayeredVpnService')
        for name in names:(src/R.APP/(name+'.java')).write_text((R.JAVA/(name+'.java')).read_text())
        (src/R.APP/'OrderedRuntimeTest.java').write_text(HARNESS)
        subprocess.run(['javac','--release','17','-encoding','UTF-8','-proc:none','-cp',str(jar),'-d',str(classes),*map(str,src.rglob('*.java'))],check=True,timeout=60)
        for count in (3,4,8):
            subprocess.run(['java','-cp',os.pathsep.join((str(classes),str(jar))),'com.eabusham.routervpn.OrderedRuntimeTest',str(count)],check=True,timeout=90)
        original=(R.JAVA/'AndroidNodeChainSession.java').read_text()
        guard='capture.close(); proofClosed = true;'
        assert original.count(guard)==1
        changed=src/R.APP/'AndroidNodeChainSession.java';changed.write_text(original.replace(guard,'proofClosed = true;',1))
        subprocess.run(['javac','--release','17','-encoding','UTF-8','-proc:none','-cp',os.pathsep.join((str(classes),str(jar))),'-d',str(classes),str(changed)],check=True,timeout=60)
        failed=subprocess.run(['java','-cp',os.pathsep.join((str(classes),str(jar))),'com.eabusham.routervpn.OrderedRuntimeTest'],capture_output=True,text=True,timeout=90)
        assert failed.returncode!=0 and 'imported SS failed shared join discarded original source' in failed.stdout+failed.stderr,failed.stdout+failed.stderr
        print('Rejected imported SS original-owner proof-drain omission mutation')
if __name__=='__main__':main()
