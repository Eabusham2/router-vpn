#!/usr/bin/env python3
"""Exercise ordinary and qualified Local Java owners/history. Optionally replay actual peer receipts."""
from pathlib import Path
import argparse,importlib.util,json,os,subprocess,tempfile,shutil
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
# The native double exposes the same two qualified source layouts used by the
# peer test. Resetting its count below exercises unavailable/stale native proof.
SOURCES[NATIVE+'RouterNodeChain.java']=SOURCES[NATIVE+'RouterNodeChain.java'].replace(
    'public int extendedLocalNodeCount(){return 0;}',
    'public boolean qualified=true;public int extendedLocalNodeCount(){return qualified&&(count==9||count==16)?count:0;}')
SOURCES[APP+'AndroidNodeStore.java']=SOURCES[APP+'AndroidNodeStore.java'].replace(
    'final boolean imported=false;', 'boolean imported;').replace(
    'selected.add(i==count-1?finalMode:prefixMode);',
    'boolean interior=!pairedFixture&&count>8&&i>=Math.max(1,mixedPackets)&&i<count-1;list.get(i).imported=interior;selected.add(interior?"shadowsocks":i==count-1?finalMode:prefixMode);')
SOURCES[NATIVE+'RouterOrderedLatency.java']=SOURCES[NATIVE+'RouterOrderedLatency.java'].replace(
    'Integer.parseInt(node.substring(node.length()-1))', 'Integer.parseInt(node.substring(node.length()-2),16)').replace(
    'boolean pub=false;', 'boolean pub=plan.count>8&&position>=Math.max(1,plan.mixedPackets)&&position<plan.count-1;').replace(
    '"Cumulative path through custom node 2 of 3 → Cloudflare edge"',
    '"Cumulative path through custom node "+(position+1)+" of "+plan.count+" → Cloudflare edge"')
SOURCES[APP+'AndroidNodeStore.java']=SOURCES[APP+'AndroidNodeStore.java'].replace('static final int PHYSICAL_TRAVERSAL_DEPTH','static boolean pairedFixture;static int mixedPackets;static final int PHYSICAL_TRAVERSAL_DEPTH')
SOURCES[APP+'AndroidNodeChainCapture.java']=SOURCES[APP+'AndroidNodeChainCapture.java'].replace('final boolean multipleImported=false;', 'final boolean multipleImported;').replace('this.source=source;', 'this.source=source;multipleImported=source.members.size()>8&&source.members.get(source.members.size()-2).imported;').replace('config="{', 'plan.paired=source.members.size()>8&&!multipleImported;plan.mixedPackets=AndroidNodeStore.mixedPackets;config="{')
SOURCES[NATIVE+'RouterNodeChain.java']=SOURCES[NATIVE+'RouterNodeChain.java'].replace('public boolean qualified', 'public boolean paired;public int mixedPackets;public boolean qualified').replace('public int extendedMixedLocalPacketCount(){return 0;}','public int extendedMixedLocalPacketCount(){return mixedPackets;}')
SOURCES[NATIVE+'RouterOrderedLatency.java']=SOURCES[NATIVE+'RouterOrderedLatency.java'].replace('boolean pub=plan.count>8','boolean pub=!plan.paired&&plan.count>8')
for name,source in F.SOURCES.items():
 if name.startswith('android/'):SOURCES[name]=source
HARNESS=R.HARNESS[:R.HARNESS.index(' static void success()')].replace('OrderedRuntimeTest','OrdinaryFiftyTest')+F.HARNESS[F.HARNESS.index(' static final class Outcome'):F.HARNESS.index(' static void success()')]+r'''
 static AndroidOrderedLatencyStore.Record completed(org.json.JSONObject receipt,String source,String config,int position,String node,String kind,int depth,String execution)throws Exception{
  String request=receipt.getString("request_id");String status=new org.json.JSONObject().put("request_id",request).put("stage","complete").put("complete",true).put("drained",true).put("results",new org.json.JSONArray().put(receipt.getJSONObject("result"))).toString();
  return AndroidOrderedLatencyStore.completed(status,receipt.toString(),request,source,config,position,node,kind,execution,false,depth);
 }
 static void replay(Fixture f,org.json.JSONArray layouts)throws Exception{
  for(int j=0;j<layouts.length();j++){
   var plan=layouts.getJSONObject(j);var nodes=plan.getJSONArray("nodes");var receipts=plan.getJSONArray("receipts");int depth=nodes.length();
   check((depth==9||depth==16)&&receipts.length()==depth,"incomplete peer receipt layout");
   String source=plan.getString("source"),config=plan.getString("config");
   for(int position=0;position<depth;position++){
    final int slot=position;var member=nodes.getJSONObject(slot);var raw=receipts.getJSONObject(slot);String node=member.getString("profile_id"),kind=member.optString("kind","private-node");
    check(member.getInt("position")==slot&&kind.equals(slot==0||slot==depth-1?"private-node":"public-path"),"original inventory changed");
    var record=completed(raw,source,config,slot,node,kind,depth,"");AndroidOrderedLatencyStore.save(f.service,record,()->{});
    var read=AndroidOrderedLatencyStore.load(f.service,source,config,slot,node,kind,depth);
    check(read.raw.equals(record.raw)&&read.detail().contains("50 successful"),"actual peer result was lost");
    reject(()->completed(raw,source,config,slot,node,kind,0,""),"an unqualified owner admitted a deep peer receipt");
    reject(()->completed(raw,source,config,slot,node,kind,depth==9?16:9,""),"a different depth admitted a peer receipt");
    reject(()->completed(raw,source,config,slot,node,kind,depth,"server"),"selected Server admitted an extended receipt");
    reject(()->completed(raw,source,config,slot,node,kind,depth,"local"),"selected Compare admitted an extended receipt");
    reject(()->completed(raw,config,source,slot,node,kind,depth,""),"changed original source/config admitted a peer receipt");
    reject(()->completed(raw,source,config,slot,"foreign",kind,depth,""),"another original node admitted a peer receipt");
    reject(()->AndroidOrderedLatencyStore.load(f.service,source,config,slot,node,kind),"ordinary history adopted a deep native receipt");
    var stored=Files.readAllBytes(f.files.resolve(AndroidOrderedLatencyStore.FILE_NAME));
    var partial=new org.json.JSONObject(raw.toString());partial.getJSONObject("result").getJSONObject("benchmark").getJSONObject("distribution").put("samples",49);
    reject(()->completed(partial,source,config,slot,node,kind,depth,""),"49 responses displaced completed evidence");
    check(Arrays.equals(stored,Files.readAllBytes(f.files.resolve(AndroidOrderedLatencyStore.FILE_NAME))),"rejected receipt changed retained history");
   }
  }
 }
 static void extended(boolean paired,int packets)throws Exception{
  AndroidNodeStore.pairedFixture=paired;AndroidNodeStore.mixedPackets=packets;
  Method progress=AndroidOrderedLatencyDialog.class.getDeclaredMethod("progressText",String.class);progress.setAccessible(true);
  for(int count:new int[]{9,16})try(Fixture f=new Fixture(count,"wg","shadowsocks")){
   f.connected();var chain=f.owner();var targets=LayeredVpnService.orderedLatencyTargets();
   check(targets.size()==count&&chain.orderedLatencyEligible(),"extended Local targets were truncated");
   var dialog=new AndroidOrderedLatencyDialog(new android.app.Activity());
   for(var target:targets){
    boolean endpoint=target.position==0||target.position==count-1;
    check(target.extendedCount==count&&target.pairedPrefixNodes==packets&&target.kind.equals(paired||endpoint||target.position<packets?"private-node":"public-path"),"qualified history owner/response kind changed");
    set(dialog,"target",target);String stage="node "+(target.position+1)+": response 50/50";
    check(progress.invoke(dialog,stage).toString().contains("50 of 50"),"extended progress hid the captured node");
    check(!progress.invoke(dialog,"node 99: response 50/50").toString().contains("50 of 50"),"progress accepted another node");
    var value=measure(target);
    check(value.error==null&&value.record!=null,"extended worker refused original position: "+value.error);
    var read=AndroidOrderedLatencyStore.load(f.service,target.source,target.config,target.position,target.node,target.kind,target.extendedCount,packets);
    check(read.raw.equals(value.record.raw)&&read.count==count&&read.extendedPaired==paired&&read.pairedPrefixNodes==packets,"extended worker/history lost the original record");
    if(!endpoint){
     var raw=new org.json.JSONObject(read.raw);String req=raw.getString("request_id");
     String status=new org.json.JSONObject().put("request_id",req).put("stage","complete").put("complete",true).put("drained",true).put("results",new org.json.JSONArray().put(raw.getJSONObject("result"))).toString();
     if(packets==0)reject(()->AndroidOrderedLatencyStore.completed(status,read.raw,req,target.source,target.config,target.position,target.node,target.kind,"",false,count,!paired),"extended interior admitted the other source family");
     reject(()->AndroidOrderedLatencyStore.completed(status,read.raw,req,target.source,target.config,target.position,target.node,target.kind,"server",false,count,paired),"extended ordinary interior admitted Server owner");
    }
    if(packets>0)reject(()->AndroidOrderedLatencyStore.load(f.service,target.source,target.config,target.position,target.node,target.kind,count,packets+1),"foreign packet boundary disclosed stored mixed receipt");
    reject(()->AndroidOrderedLatencyStore.load(f.service,target.source,target.config,target.position,target.node,target.kind),"unqualified history disclosed a deep receipt");
   }
   chain.capture.plan.qualified=false;
   reject(()->LayeredVpnService.orderedLatencyTargets(),"uncertified original native plan admitted extended targets");
   f.stop();
  }
 }
 public static void main(String[] args)throws Exception{
  for(int count=2;count<=8;count++)try(Fixture f=new Fixture(count,count%2==0?"wg":"awg2-fast",count%2==0?"shadowsocks":"hysteria2")){
   f.connected();var chain=f.owner();check(!chain.typedNative()&&chain.orderedLatencyEligible(),"ordinary captured Local path unavailable");
   var original=get(f.service,"hopMeasurement");var targets=LayeredVpnService.orderedLatencyTargets();check(targets.size()==count,"ordinary inventory truncated");
   for(var target:targets){check(target.kind.equals("private-node"),"ordinary paired middle became public");var value=measure(target);check(value.error==null&&value.record!=null,"ordinary benchmark rejected: "+value.error);check(value.record.count==count&&value.record.position==target.position&&value.record.raw.equals(saved(f,target).raw),"ordinary history changed captured count/position");check(RouterOrderedLatency.latest.closed&&!AndroidMTUMeasurementGate.held(),"ordinary history preceded original facade join");}
   var value=measure(targets.get(count-1));check(value.error==null&&original==get(f.service,"hopMeasurement")&&((RouterHopMeasurement)original).closes==0,"ordinary Retest replaced borrowed service");
   var previous=saved(f,targets.get(0));RouterOrderedLatency.fault="49";value=measure(targets.get(0));check(value.error!=null&&saved(f,targets.get(0)).raw.equals(previous.raw),"ordinary failed50 replaced history");RouterOrderedLatency.reset();
   f.stop();
  }
  extended(false,0);extended(true,0);extended(false,2);
  if(args.length==1)try(Fixture f=new Fixture(3)){replay(f,new org.json.JSONArray(Files.readString(Path.of(args[0]))));}
  System.out.println("Android Local fifty: "+checks+" checks; 35 ordinary and 75 qualified positions across imported, paired and mixed families; native/OS facade doubled"+(args.length==0?".":"; additionally replayed 25 actual peer receipts."));
 }
}'''
PEER_PLAN = r'''package main
import (
    "encoding/json"
    "os"
    "router-vpn/internal/mobilemultihop"
)
func main() {
    input, err := os.ReadFile(os.Args[1]); if err != nil { panic(err) }
    chain, err := mobilemultihop.ParseNodeChainLaunchInput(string(input)); clear(input)
    if err != nil { panic("original native launch input failed admission") }
    if err = json.NewEncoder(os.Stdout).Encode(struct{
        Count int `json:"count"`
        Source string `json:"source"`
        Config string `json:"config"`
        Nodes []mobilemultihop.NodeChainProof `json:"nodes"`
    }{chain.ExtendedLocalNodeCount(),chain.SourceSHA256(),chain.ConfigSHA256(),chain.ProofInventory()}); err!=nil { panic(err) }
}
'''


def peer_layouts(log, originals, work):
 """Independently re-admit the actual source before accepting any peer row."""
 import re
 lines=log.read_text().splitlines()
 rows={9:[],16:[]}
 inventories={}
 for line in lines:
  match=re.search(r'QUALIFIED_ORIGINAL_(NODES|RECEIPT) (9|16) (.+)$',line)
  if match:
   name,count,value=match[1],int(match[2]),json.loads(match[3])
   if name=='NODES':
    if count in inventories:raise ValueError('duplicate peer inventory')
    inventories[count]=value
   else:rows[count].append(value)
 if set(inventories)!={9,16} or not lines or lines[-1].strip()!='PASS':
  raise ValueError('incomplete original peer run')
 helper=work/'admit-plan'
 with tempfile.TemporaryDirectory(prefix='android-connection-profiles-',dir=ROOT) as module_dir:
  source=Path(module_dir)/'main.go';source.write_text(PEER_PLAN)
  subprocess.run(['go','build','-o',str(helper),str(source)],cwd=ROOT,check=True,timeout=90)
 layouts=[]
 for count in (9,16):
  result=subprocess.run([str(helper),str(originals/f'original-{count}.json')],capture_output=True,text=True,check=True,timeout=15)
  plan=json.loads(result.stdout)
  if plan['count']!=count or plan['nodes']!=inventories[count] or [v['position'] for v in rows[count]]!=list(range(count)):
   raise ValueError('source, proof inventory or original peer positions changed')
  if len({v['generation_sha256'] for v in rows[count]})!=1 or len({v['request_id'] for v in rows[count]})!=count:
   raise ValueError('peer receipts crossed generations or requests')
  plan['receipts']=rows[count];layouts.append(plan)
 path=work/'original-peer-results.json';path.write_text(json.dumps(layouts))
 return path

def main():
 parser=argparse.ArgumentParser(description=__doc__)
 parser.add_argument('--peer-log',type=Path,help='completed 9/16 native peer test log with original inventory and receipts')
 parser.add_argument('--originals',type=Path,help='private directory containing the matching canonical original-9/16.json launch inputs')
 args=parser.parse_args()
 if bool(args.peer_log)!=bool(args.originals):parser.error('--peer-log and --originals must identify the same completed run')
 jar=Path(os.environ.get('ANDROID_JSON_JAR','/usr/share/java/com.android.json.jar'))
 with tempfile.TemporaryDirectory(prefix='ordinary-fifty-java-') as d:
  d=Path(d);src=d/'src';out=d/'classes'
  for name,value in SOURCES.items():
   p=src/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_text(value)
  names=('AndroidHomeStateStore','AndroidConnectionSelection','AndroidNodeChainSession','AndroidNodeChainMTUPlatform','AndroidNodeChainRuntime','LayeredVpnService','AndroidOrderedLatencyStore','AndroidOrderedExecutionLatencyCapture','AndroidOrderedExecutionLatencyStore','AndroidOrderedLatencySourceTransaction','AndroidOrderedLatencyBenchmark','AndroidMTUMeasurementGate','AndroidOrderedLatencyDialog')
  for name in names:(src/APP/(name+'.java')).write_text((JAVA/(name+'.java')).read_text())
  (src/APP/'OrdinaryFiftyTest.java').write_text(HARNESS)
  subprocess.run(['javac','--release','17','-encoding','UTF-8','-proc:none','-cp',str(jar),'-d',str(out),*map(str,src.rglob('*.java'))],check=True,timeout=60)
  cp=os.pathsep.join((str(out),str(jar)))
  peer=[str(peer_layouts(args.peer_log,args.originals,d))] if args.peer_log else []
  subprocess.run(['java','-cp',cp,'com.eabusham.routervpn.OrdinaryFiftyTest',*peer],check=True,timeout=90)
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
