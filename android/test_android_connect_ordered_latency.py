#!/usr/bin/env python3
"""Run actual Android CONNECT fifty callers for HTTP and HTTPS middle nodes.

Reuses the complete existing fifty family/control inventory, substituting only
its explicit native schema-four boundary. Shipping service/session/UI/store run
unchanged. This is not generated SDK or encrypted-network acceptance.
"""
from pathlib import Path
import ast
import importlib.util
import os
import shutil
import subprocess
import tempfile
ROOT=Path(__file__).resolve().parents[1]
JAVA=ROOT/'android/app/src/main/java/com/eabusham/routervpn'
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,ROOT/path)
    value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value
F=load('connect_fifty_shared_families','android/test_android_ordered_latency.py')
C=load('connect_fifty_native_boundary','android/test_android_node_chain_connect_runtime.py')
APP,NATIVE=F.APP,F.NATIVE
SOURCES=dict(F.SOURCES)
for name in ('AndroidNodeChainCapture','AndroidNodeChainSOCKSCapture'):
    SOURCES[APP+name+'.java']=C.SOURCES[APP+name+'.java']
SOURCES.pop(APP+'AndroidNodeChainCONNECTCapture.java')
SOURCES[APP+'AndroidNodeStore.java']=C.SOURCES[APP+'AndroidNodeStore.java'].replace('final boolean imported=false;','final boolean imported;').replace('this.id=id;profileId=', 'this.id=id;imported=id.endsWith("2");profileId=')
SOURCES[NATIVE+'RouterNodeChainSOCKS.java']=C.SOURCES[NATIVE+'RouterNodeChainSOCKS.java']
SOURCES[NATIVE+'RouterNodeChainCONNECT.java']=C.SOURCES[NATIVE+'RouterNodeChainCONNECT.java'].replace('public final String input;','public RouterHopMeasurement measurement;public final String input;')
SOURCES[NATIVE+'Libbox.java']=C.SOURCES[NATIVE+'Libbox.java'].replace('plan.hopCalls++;return new RouterHopMeasurement();','plan.hopCalls++;return plan.measurement=new RouterHopMeasurement();').replace('throw new IllegalStateException("No CONNECT fifty in ordinary host fixture");','if(!plan.healthy()||plan.server!=server||plan.measurement!=measurement||RouterOrderedLatency.mtuOccupied)throw new AssertionError("CONNECT facade borrowed another native measurement");return new RouterOrderedLatency(plan,measurement);')
SOURCES[NATIVE+'RouterOrderedLatency.java']=F.SOURCES[NATIVE+'RouterOrderedLatency.java'].replace('RouterNodeChainSOCKS','RouterNodeChainCONNECT')
HARNESS=F.HARNESS.replace('OrderedFiftyTest','CONNECTFiftyTest').replace('RouterNodeChainSOCKS','RouterNodeChainCONNECT').replace('.capture.socks','.capture.connect').replace('private-socks-credentials','private-connect-credentials').replace('public static void main(String[] args)', 'static void originalMain(String[] args)')
HARNESS=HARNESS.replace('targets.size()==3&&targets.get(1).kind.equals("public-path")','targets.size()==3&&targets.get(1).kind.equals("public-path")&&targets.get(1).label.contains(RouterNodeChainCONNECT.transport)&&f.owner().capture.socks==null&&f.owner().capture.plan==null')
HARNESS=HARNESS.replace('static void originalMain(String[] args)',r'''static void destroyedFifty()throws Exception{RouterOrderedLatency.reset();try(Fixture f=new Fixture(3)){
  f.connected();var captured=f.owner();var target=LayeredVpnService.orderedLatencyTargets().get(0);var owner=LayeredVpnService.captureOrderedLatency("d".repeat(32),target);owner.start();var facade=RouterOrderedLatency.latest;var probe=(RouterHopMeasurement)get(f.service,"hopMeasurement");var server=(CommandServer)get(f.service,"commandServer");int boxes=CommandServer.created;
  RouterOrderedLatency.holdClose=true;f.service.onDestroy();check(!captured.released()&&!((ExecutorService)get(f.service,"executor")).isShutdown()&&probe.closes==0&&!server.closed&&get(captured,"orderedLatency")==facade,"destroyed CONNECT fifty lost original facade before join");
  RouterOrderedLatency.holdClose=false;new NativeSingBoxController(f.service).stopNodeChain(captured.sessionId);await(captured::released,"destroyed CONNECT fifty could not retry original cleanup");check(facade.closed&&probe.closes>0&&server.closed&&CommandServer.created==boxes,"destroyed CONNECT fifty replaced its original service or lost cleanup");
 }}
 static void originalMain(String[] args)''')
HARNESS=HARNESS[:HARNESS.rfind('}')]+r'''
 public static void main(String[] args)throws Exception{
  if(args.length<1||!List.of("http-connect","https-connect").contains(args[0]))throw new AssertionError("Explicit CONNECT middle transport required");
  RouterNodeChainCONNECT.transport=args[0];if(args.length==1||args[1].equals("destroyed")){destroyedFifty();System.out.println("CONNECT fifty destruction passed: "+args[0]);}if(args.length==1||!args[1].equals("destroyed"))originalMain(args.length>1?new String[]{args[1]}:new String[0]);
  System.out.println("CONNECT fifty transport passed: "+args[0]);
 }
}'''

def original_controls():
    tree=ast.parse((ROOT/'android/test_android_ordered_latency.py').read_text())
    main=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='main')
    controls=next(n for n in ast.walk(main) if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='controls' for t in n.targets))
    value=ast.literal_eval(controls.value)
    assert len(value)==9,'Original fifty controls changed; review the full CONNECT inventory'
    return tuple(tuple(v.replace('capture.socks','capture.connect') if isinstance(v,str) else v for v in row) for row in value)

def main():
    jar=Path(os.environ.get('ANDROID_JSON_JAR','/usr/share/java/com.android.json.jar'))
    with tempfile.TemporaryDirectory(prefix='routervpn-connect-fifty-') as directory:
        work=Path(directory);src=work/'src';classes=work/'classes'
        for name,text in SOURCES.items():
            target=src/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_text(text)
        names=('AndroidHomeStateStore','AndroidConnectionSelection','AndroidNodeChainCONNECTCapture','AndroidNodeChainSession','AndroidNodeChainMTUPlatform','AndroidNodeChainRuntime','LayeredVpnService','AndroidOrderedLatencyStore','AndroidOrderedLatencyBenchmark','AndroidOrderedLatencyDialog','AndroidMTUMeasurementGate')
        originals={name:(JAVA/(name+'.java')).read_text() for name in names}
        for name,text in originals.items():(src/APP/(name+'.java')).write_text(text)
        (src/APP/'CONNECTFiftyTest.java').write_text(HARNESS)
        subprocess.run(['javac','-J-Xmx512m','--release','17','-encoding','UTF-8','-proc:none','-cp',str(jar),'-d',str(classes),*map(str,src.rglob('*.java'))],check=True,timeout=60)
        for transport in ('http-connect','https-connect'):
            subprocess.run(['java','-Xmx512m','-cp',os.pathsep.join((str(classes),str(jar))),'com.eabusham.routervpn.CONNECTFiftyTest',transport],check=True,timeout=120)
        controls=original_controls()+(
            ('LayeredVpnService','if(nodeChainSession!=null)try{nodeChainSession.closeOrderedLatency();}','if(false)try{nodeChainSession.closeOrderedLatency();}','destroyed','destroyed CONNECT fifty lost original facade before join'),
            ('AndroidNodeChainSession','capture.connect!=null?Libbox.routerNodeChainCONNECTNewLatencyBenchmark(capture.connect.plan,server,measurement)\n                :','', 'success','complete benchmark not adopted'),
        )
        for i,(name,old,new,family,witness) in enumerate(controls):
            assert originals[name].count(old)==1,(name,old)
            target=work/f'mutant-{i}'/(name+'.java');target.parent.mkdir();target.write_text(originals[name].replace(old,new))
            out=work/f'negative-{i}';shutil.copytree(classes,out);cp=os.pathsep.join((str(out),str(jar)))
            subprocess.run(['javac','-J-Xmx512m','--release','17','-proc:none','-cp',cp,'-d',str(out),str(target)],check=True,timeout=60)
            for transport in ('http-connect','https-connect'):
                result=subprocess.run(['java','-Xmx512m','-cp',cp,'com.eabusham.routervpn.CONNECTFiftyTest',transport,family],capture_output=True,text=True,timeout=60)
                assert result.returncode!=0 and witness in result.stderr,(transport,family,result.stdout,result.stderr)
                print('CONNECT fifty causal control rejected: '+str(i)+'/'+transport+'/'+family,flush=True)
        print('CONNECT fifty: both transports, destruction plus all eight original families and eleven compiled controls per transport passed')
if __name__=='__main__':main()
