#!/usr/bin/env python3
"""Execute ordinary2–8 shipping Java owners/history; native and Android boundaries are explicit doubles."""
from pathlib import Path
import importlib.util,os,subprocess,tempfile,shutil
ROOT=Path(__file__).resolve().parents[1];JAVA=ROOT/'android/app/src/main/java/com/eabusham/routervpn'
def load(name,path):
 spec=importlib.util.spec_from_file_location(name,ROOT/path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
R=load('ordinary_runtime','android/test_android_node_chain_runtime.py');F=load('typed_fifty','android/test_android_ordered_latency.py');APP,NATIVE=R.APP,R.NATIVE
SOURCES=dict(R.SOURCES)
for name in (APP+'AndroidPrivateFileStore.java',APP+'AndroidTorProfile.java'):SOURCES[name]=F.SOURCES[name]
SOURCES.pop(APP+'AndroidOrderedLatencyStore.java')
SOURCES[NATIVE+'RouterNodeChain.java']=SOURCES[NATIVE+'RouterNodeChain.java'].replace('public CommandServer server;','public RouterHopMeasurement measurement;public CommandServer server;')
SOURCES[NATIVE+'Libbox.java']=SOURCES[NATIVE+'Libbox.java'].replace('return new RouterHopMeasurement();','return plan.measurement=new RouterHopMeasurement();',1).replace('throw new IllegalStateException("No generic fifty in ordinary host fixture");','if(!plan.healthy()||plan.server!=server||plan.measurement!=measurement)throw new AssertionError("ordinary facade borrowed foreign measurement");return new RouterOrderedLatency(plan,measurement);')
SOURCES[NATIVE+'RouterOrderedLatency.java']=F.SOURCES[NATIVE+'RouterOrderedLatency.java'].replace('RouterNodeChainSOCKS','RouterNodeChain').replace('boolean pub=position==1;','boolean pub=false;').replace('position==2?"exit"','position==plan.count-1?"exit"').replace('+(position+1)+" of 3"','+(position+1)+" of "+plan.count')
SOURCES[NATIVE+'RouterNodeChain.java']=SOURCES[NATIVE+'RouterNodeChain.java'][:-1]+'public String sourceSHA256(){return "a".repeat(64);}public String configSHA256(){return "b".repeat(64);}}'
SOURCES[NATIVE+'Libbox.java']=SOURCES[NATIVE+'Libbox.java'][:-1]+'public static void routerValidatePrivateNodeJSON(String input)throws Exception{new org.json.JSONObject(input);}}'
HARNESS=R.HARNESS[:R.HARNESS.index(' static void success()')].replace('OrderedRuntimeTest','OrdinaryFiftyTest')+F.HARNESS[F.HARNESS.index(' static final class Outcome'):F.HARNESS.index(' static void success()')]+r'''
 public static void main(String[] args)throws Exception{
  for(int count=2;count<=8;count++)try(Fixture f=new Fixture(count,count%2==0?"wg":"awg2-fast",count%2==0?"shadowsocks":"hysteria2")){
   f.connected();var chain=f.owner();check(!chain.typedNative()&&chain.orderedLatencyEligible(),"ordinary captured Local path unavailable");
   var original=get(f.service,"hopMeasurement");var targets=LayeredVpnService.orderedLatencyTargets();check(targets.size()==count,"ordinary inventory truncated");
   for(var target:targets){check(target.kind.equals("private-node"),"ordinary paired middle became public");var value=measure(target);check(value.error==null&&value.record!=null,"ordinary benchmark rejected: "+value.error);check(value.record.count==count&&value.record.position==target.position&&value.record.raw.equals(saved(f,target).raw),"ordinary history changed captured count/position");check(RouterOrderedLatency.latest.closed&&!AndroidMTUMeasurementGate.held(),"ordinary history preceded original facade join");}
   var value=measure(targets.get(count-1));check(value.error==null&&original==get(f.service,"hopMeasurement")&&((RouterHopMeasurement)original).closes==0,"ordinary Retest replaced borrowed service");
   var previous=saved(f,targets.get(0));RouterOrderedLatency.fault="49";value=measure(targets.get(0));check(value.error!=null&&saved(f,targets.get(0)).raw.equals(previous.raw),"ordinary failed50 replaced history");RouterOrderedLatency.reset();
   f.stop();
  }
  System.out.println("Android ordinary fifty: "+checks+" checks; 35 positions2–8; native/OS boundaries doubled.");
 }
}'''
def main():
 jar=Path(os.environ.get('ANDROID_JSON_JAR','/usr/share/java/com.android.json.jar'))
 with tempfile.TemporaryDirectory(prefix='ordinary-fifty-java-') as d:
  d=Path(d);src=d/'src';out=d/'classes'
  for name,value in SOURCES.items():
   p=src/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_text(value)
  names=('AndroidHomeStateStore','AndroidConnectionSelection','AndroidNodeChainSession','AndroidNodeChainMTUPlatform','AndroidNodeChainRuntime','LayeredVpnService','AndroidOrderedLatencyStore','AndroidOrderedLatencyBenchmark','AndroidMTUMeasurementGate')
  for name in names:(src/APP/(name+'.java')).write_text((JAVA/(name+'.java')).read_text())
  (src/APP/'OrdinaryFiftyTest.java').write_text(HARNESS)
  subprocess.run(['javac','--release','17','-encoding','UTF-8','-proc:none','-cp',str(jar),'-d',str(out),*map(str,src.rglob('*.java'))],check=True,timeout=60)
  cp=os.pathsep.join((str(out),str(jar)))
  subprocess.run(['java','-cp',cp,'com.eabusham.routervpn.OrdinaryFiftyTest'],check=True,timeout=90)
  for name,old,new,witness in [
   ('generic-dispatch','Libbox.routerNodeChainNewLatencyBenchmark(capture.plan,server,measurement)','Libbox.routerNodeChainNewLatencyBenchmark(capture.plan,server,new io.nekohasekai.libbox.RouterHopMeasurement())','ordinary facade borrowed foreign measurement'),
   ('generic-eligibility','(typedNative() || capture.plan != null)','typedNative()','ordinary captured Local path unavailable')]:
   original=(JAVA/'AndroidNodeChainSession.java').read_text();assert original.count(old)==1
   p=d/name/'AndroidNodeChainSession.java';p.parent.mkdir();p.write_text(original.replace(old,new))
   classes=d/(name+'-classes');shutil.copytree(out,classes);cp=os.pathsep.join((str(classes),str(jar)))
   subprocess.run(['javac','--release','17','-proc:none','-cp',cp,'-d',str(classes),str(p)],check=True,timeout=60)
   r=subprocess.run(['java','-cp',cp,'com.eabusham.routervpn.OrdinaryFiftyTest'],capture_output=True,text=True,timeout=90)
   assert r.returncode!=0 and witness in r.stdout+r.stderr,(name,r.stdout,r.stderr)
   print('Rejected ordinary50 causal control: '+name,flush=True)
if __name__=='__main__':main()
