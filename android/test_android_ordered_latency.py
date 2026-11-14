#!/usr/bin/env python3
"""Execute shipping ordered fifty service/session/worker/store/dialog callers.

Native exchanges, SDK widgets and atomic-file syscalls are explicit boundaries.
This is Java ownership/persistence evidence, not fifty encrypted exchanges or APK
acceptance. Shared native acceptance is an independent gate.
"""
from pathlib import Path
import importlib.util
import os
import shutil
import subprocess
import tempfile
ROOT=Path(__file__).resolve().parents[1]
JAVA=ROOT/'android/app/src/main/java/com/eabusham/routervpn'
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,ROOT/path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
S=load('ordered_fifty_typed_host','android/test_android_node_chain_socks_runtime.py')
U=load('ordered_fifty_ui','android/test_android_tor_form.py')
APP,NATIVE=S.APP,S.NATIVE
SOURCES=dict(S.SOURCES)
SOURCES.pop(APP+'AndroidOrderedLatencyStore.java')
SOURCES[APP+'AndroidTorProfile.java']=SOURCES[APP+'AndroidTorProfile.java'].replace('return "";} }','return java.nio.charset.StandardCharsets.UTF_8.newDecoder().onMalformedInput(java.nio.charset.CodingErrorAction.REPORT).decode(java.nio.ByteBuffer.wrap(data)).toString();} }')
SOURCES[APP+'AndroidNodeStore.java']=SOURCES[APP+'AndroidNodeStore.java'].replace('final boolean imported=false;','final boolean imported;').replace('this.id=id;profileId=', 'this.id=id;imported=id.endsWith("2");profileId=')
SOURCES[NATIVE+'RouterNodeChainSOCKS.java']=SOURCES[NATIVE+'RouterNodeChainSOCKS.java'].replace('public final String input;','public RouterHopMeasurement measurement;public final String input;')
SOURCES[NATIVE+'Libbox.java']=SOURCES[NATIVE+'Libbox.java'].replace('plan.hopCalls++;return new RouterHopMeasurement();','plan.hopCalls++;return plan.measurement=new RouterHopMeasurement();').replace('throw new IllegalStateException("No ordered fifty in ordinary host fixture");','if(!plan.healthy()||plan.server!=server||plan.measurement!=measurement||RouterOrderedLatency.mtuOccupied)throw new AssertionError("facade borrowed another native measurement");return new RouterOrderedLatency(plan,measurement);')
SOURCES[NATIVE+'RouterOrderedLatency.java']=r'''package io.nekohasekai.libbox;
import org.json.*;import java.util.concurrent.*;
public class RouterOrderedLatency {
 public static volatile RouterOrderedLatency latest;public static volatile String fault="";public static volatile Runnable afterDrain,beforeStart;public static volatile boolean holdClose,holdDrain,holdResponses;public static int factories;public static volatile boolean mtuOccupied;public static volatile CountDownLatch quiesceEntered,quiesceRelease;
 public final RouterNodeChainSOCKS plan;public final RouterHopMeasurement measurement;public String request,node;public volatile int starts,cancels,drains,closes;public boolean drained,closed;public final CountDownLatch closeEntered=new CountDownLatch(1),drainEntered=new CountDownLatch(1);
 public RouterOrderedLatency(RouterNodeChainSOCKS p,RouterHopMeasurement m){plan=p;measurement=m;latest=this;factories++;}
 public void start(String request,String node)throws Exception{starts++;this.request=request;this.node=node;Runnable hook=beforeStart;beforeStart=null;if(hook!=null)hook.run();if(fault.equals("start"))throw new IllegalStateException("native start refused");}
 public void cancel(String request){cancels++;}
 public void drain(String request)throws Exception{drains++;drainEntered.countDown();if(holdDrain)throw new IllegalStateException("original drain pending");drained=true;Runnable hook=afterDrain;afterDrain=null;if(hook!=null)hook.run();}
 public void close()throws Exception{closes++;closeEntered.countDown();if(holdClose)throw new IllegalStateException("original facade pending");closed=true;}
 public JSONObject receipt()throws Exception{
  int position=Integer.parseInt(node.substring(node.length()-1))-1;boolean pub=position==1;
  JSONObject distribution=new JSONObject().put("samples",fault.equals("49")?49:50).put("min_ms",1).put("median_ms",2).put("average_ms",2.1).put("p90_ms",3).put("max_ms",4).put("jitter_ms",0.2);
  JSONObject benchmark=new JSONObject().put("schema",1).put("measurement",pub?"routed-https-response-after-tls":"routed-private-response-including-connection").put("endpoint",pub?"https://speed.cloudflare.com/__down?bytes=1":"").put("attempts",50).put("failed",0).put("distribution",distribution).put("trimmed_mean_ms",2);
  JSONObject row=new JSONObject().put("node_id",node).put("role",position==0?"entry":position==2?"exit":"intermediate").put("kind",pub?"public-path":"private-node").put("label",pub?"Cumulative path through custom node 2 of 3 → Cloudflare edge":"Cumulative path through node "+(position+1)+" of 3").put("ready",true).put("benchmark",benchmark);
  if(fault.equals("count"))row.put("label","Cumulative path through node 1 of 2");
  return new JSONObject().put("schema",1).put("source_sha256",plan.sourceSHA256()).put("config_sha256",plan.configSHA256()).put("generation_sha256","c".repeat(64)).put("position",position).put("node_id",node).put("request_id",request).put("measured_at",System.currentTimeMillis()).put("result",row);
 }
 public String statusJSON()throws Exception{
  JSONObject value=new JSONObject().put("request_id",request).put("stage",holdResponses?"node 1: response 49/50":"complete").put("complete",!holdResponses).put("drained",drained).put("results",holdResponses?new JSONArray():new JSONArray().put(receipt().getJSONObject("result")));
  if(fault.equals("last"))value.put("failure","fiftieth response failed");return value.toString();
 }
 public String savedJSON(String selected)throws Exception{if(!selected.equals(node)||!drained)throw new AssertionError("history before original worker drain");return receipt().toString();}
 public static void reset(){mtuOccupied=false;quiesceEntered=quiesceRelease=null;fault="";holdClose=holdDrain=holdResponses=false;afterDrain=beforeStart=null;latest=null;}
}'''
SOURCES[APP+'AndroidMTUSession.java']=SOURCES[APP+'AndroidMTUSession.java'].replace('public void drainForMeasurement()throws Exception{}', '''public void drainForMeasurement()throws Exception{if(io.nekohasekai.libbox.RouterOrderedLatency.quiesceEntered!=null)io.nekohasekai.libbox.RouterOrderedLatency.quiesceEntered.countDown();if(io.nekohasekai.libbox.RouterOrderedLatency.quiesceRelease!=null&&!io.nekohasekai.libbox.RouterOrderedLatency.quiesceRelease.await(5,java.util.concurrent.TimeUnit.SECONDS))throw new IllegalStateException("fixture MTU drain did not join");if(io.nekohasekai.libbox.RouterOrderedLatency.fault.equals("quiesce"))throw new IllegalStateException("MTU drain failed");io.nekohasekai.libbox.RouterOrderedLatency.mtuOccupied=false;}''')
SOURCES[APP+'AndroidPrivateFileStore.java']=r'''package com.eabusham.routervpn;
final class AndroidPrivateFileStore {
 static Runnable afterWrite;static boolean failWrite;static int writes;
 static byte[] read(java.io.File file,int limit)throws Exception{byte[] value=java.nio.file.Files.readAllBytes(file.toPath());if(value.length>limit)throw new IllegalStateException("bounded private file");return value;}
 static void write(java.io.File file,byte[] value,int limit)throws Exception{if(value.length>limit)throw new IllegalStateException("bounded private file");if(failWrite)throw new java.io.IOException("interrupted private write");java.nio.file.Files.write(file.toPath(),value);writes++;Runnable hook=afterWrite;afterWrite=null;if(hook!=null)hook.run();}
 static void remove(java.io.File file,int limit)throws Exception{java.nio.file.Files.delete(file.toPath());}
}'''
for name in ('android/view/View.java','android/widget/TextView.java','android/widget/Button.java','android/widget/LinearLayout.java','android/widget/ScrollView.java','android/graphics/Typeface.java','android/app/AlertDialog.java','android/content/DialogInterface.java'):
    SOURCES[name]=U.UI[name]
SOURCES['android/widget/TextView.java']=SOURCES['android/widget/TextView.java'].replace('public void setTextSize','public void setTextIsSelectable(boolean value){}public void setTextSize')
SOURCES['android/content/DialogInterface.java']=SOURCES['android/content/DialogInterface.java'].replace('void dismiss();','void dismiss();interface OnCancelListener{void onCancel(DialogInterface dialog);}')
SOURCES['android/app/AlertDialog.java']=SOURCES['android/app/AlertDialog.java'].replace('BUTTON_NEGATIVE=-2;','BUTTON_NEGATIVE=-2,BUTTON_NEUTRAL=-3;').replace('public void setOnDismissListener','public void setOnCancelListener(OnCancelListener value){}public boolean isShowing(){return showing;}public void setOnDismissListener').replace('public Builder setNegativeButton','public Builder setNeutralButton(CharSequence text,OnClickListener listener){return button(BUTTON_NEUTRAL,text,listener);}public Builder setNegativeButton')
SOURCES['android/app/Activity.java']=r'''package android.app;public class Activity extends android.content.Context {
 public final java.util.List<Runnable> ui=java.util.Collections.synchronizedList(new java.util.ArrayList<>());public void runOnUiThread(Runnable work){ui.add(work);}public void deliver(){java.util.List<Runnable> work;synchronized(ui){work=new java.util.ArrayList<>(ui);ui.clear();}for(Runnable value:work)value.run();}
}'''
HARNESS=S.HARNESS[:S.HARNESS.index(' static void success()')].replace('public final class TypedSOCKSHostTest','public final class OrderedFiftyTest')+r'''
 static final class Outcome implements AndroidOrderedLatencyBenchmark.Callback{
  final CountDownLatch done=new CountDownLatch(1);AndroidOrderedLatencyStore.Record record;Throwable error;LayeredVpnService.OrderedLatencyOwner owner;Runnable progress;
  public void progress(LayeredVpnService.OrderedLatencyOwner owner,String stage){this.owner=owner;if(progress!=null){Runnable hook=progress;progress=null;hook.run();}}
  public void finished(LayeredVpnService.OrderedLatencyOwner owner,AndroidOrderedLatencyStore.Record record,Throwable error){this.owner=owner;this.record=record;this.error=error;done.countDown();}
  void joined()throws Exception{check(done.await(5,TimeUnit.SECONDS),"ordered worker callback did not join");}
 }
 static AndroidOrderedLatencyStore.Record saved(Fixture f,LayeredVpnService.OrderedLatencyTarget target)throws Exception{return AndroidOrderedLatencyStore.load(f.service,target.source,target.config,target.position,target.node,target.kind);}
 static Outcome measure(LayeredVpnService.OrderedLatencyTarget target)throws Exception{Outcome result=new Outcome();new AndroidOrderedLatencyBenchmark().run(target,result);result.joined();return result;}
 static void success()throws Exception{RouterOrderedLatency.reset();try(Fixture f=new Fixture(3)){
  f.connected();var targets=LayeredVpnService.orderedLatencyTargets();check(targets.size()==3&&targets.get(1).kind.equals("public-path"),"typed node inventory lost imported middle");
  Object original=get(f.service,"hopMeasurement");int calls=f.owner().capture.socks.plan.hopCalls;
  for(var target:targets){Outcome result=measure(target);check(result.error==null&&result.record!=null,"complete benchmark not adopted: "+result.error);check(result.record.raw.equals(saved(f,target).raw),"durable exact receipt/readback lost");check(result.record.node.equals(target.node)&&!target.node.equals(f.source.members.get(target.position).id),"native profile ID was confused with local ID");check(result.record.detail().contains(target.kind.equals("public-path")?"after DNS, TCP and TLS":"includes connection"),"measurement meaning lost");check(RouterOrderedLatency.latest.closed&&!AndroidMTUMeasurementGate.held(),"receipt escaped facade join or MTU release");}
  ((AndroidMTUSession)get(f.service,"mtuSession")).token=1L;
  Outcome retest=measure(targets.get(0));check(retest.error==null,"authorized MTU epoch prevented new original-service benchmark");
  check(original==get(f.service,"hopMeasurement")&&calls==f.owner().capture.socks.plan.hopCalls,"benchmark rotated throughput service across MTU");
  check(((RouterHopMeasurement)original).closes==0,"facade close retired host throughput");
  var throughput=LayeredVpnService.captureHopMeasurement("d".repeat(32));throughput.start();throughput.cancel();throughput.drain();check(((RouterHopMeasurement)original).starts>0,"host throughput unavailable after facade close");f.stop();
 }}
 static void faults()throws Exception{for(String fault:List.of("49","last","start","count","source","mtu","config","home","cancel-before-drain","cancel-after-drain","cancel-start","stale-write","cancel-write")){RouterOrderedLatency.reset();try(Fixture f=new Fixture(3)){
  f.connected();var target=LayeredVpnService.orderedLatencyTargets().get(0);Outcome baseline=measure(target);check(baseline.error==null,"baseline history failed");String previous=saved(f,target).raw;
  AndroidOrderedLatencyBenchmark runner=new AndroidOrderedLatencyBenchmark();Outcome result=new Outcome();
  if(List.of("49","last","start","count").contains(fault))RouterOrderedLatency.fault=fault;
  if(fault.equals("source"))result.progress=()->f.source.valid=false;
  if(fault.equals("mtu"))result.progress=()->{try{((AndroidMTUSession)get(f.service,"mtuSession")).token=9L;}catch(Exception e){throw new RuntimeException(e);}};
  if(fault.equals("config"))result.progress=()->{try{set(f.service,"activeConfig","foreign");}catch(Exception e){throw new RuntimeException(e);}};
  if(fault.equals("home"))result.progress=()->AndroidHomeStateStore.begin(f.service,"new","new","libbox","foreign");
  if(fault.equals("cancel-before-drain"))result.progress=runner::cancel;
  if(fault.equals("cancel-after-drain"))RouterOrderedLatency.afterDrain=runner::cancel;
  if(fault.equals("cancel-start"))RouterOrderedLatency.beforeStart=runner::cancel;
  if(fault.equals("stale-write"))AndroidPrivateFileStore.afterWrite=()->f.source.valid=false;
  if(fault.equals("cancel-write"))AndroidPrivateFileStore.afterWrite=runner::cancel;
  runner.run(target,result);result.joined();check(result.error!=null&&result.record==null,"failed/stale/cancelled run adopted: "+fault);check(saved(f,target).raw.equals(previous),"failed run replaced previous receipt: "+fault);check(RouterOrderedLatency.latest.closed&&!runner.isRunning()&&!AndroidMTUMeasurementGate.held(),"failed run lost original cleanup: "+fault);f.source.valid=true;f.stop();
 }}}
 static void pending()throws Exception{for(String fault:List.of("drain","close","start")){RouterOrderedLatency.reset();try(Fixture f=new Fixture(3)){
  f.connected();var target=LayeredVpnService.orderedLatencyTargets().get(0);AndroidOrderedLatencyBenchmark runner=new AndroidOrderedLatencyBenchmark();Outcome result=new Outcome();
  RouterOrderedLatency.holdDrain=fault.equals("drain");RouterOrderedLatency.holdClose=!fault.equals("drain");RouterOrderedLatency.fault=fault.equals("start")?"start":"";
  runner.run(target,result);await(()->RouterOrderedLatency.latest!=null,"facade did not attach");var facade=RouterOrderedLatency.latest;
  check((fault.equals("drain")?facade.drainEntered:facade.closeEntered).await(5,TimeUnit.SECONDS),"pending original cleanup not reached");
  check(runner.isRunning()&&AndroidMTUMeasurementGate.held()&&get(f.owner(),"orderedLatency")==facade,"pending cleanup lost original facade or MTU hold");check(((RouterHopMeasurement)get(f.service,"hopMeasurement")).closes==0,"pending facade cleanup closed throughput");
  runner.cancel();RouterOrderedLatency.holdDrain=RouterOrderedLatency.holdClose=false;result.joined();check(result.error!=null&&saved(f,target)==null&&facade.closed&&!AndroidMTUMeasurementGate.held(),"cancelled late cleanup published history or retained gate");f.stop();
 }}}
 static void quiesce()throws Exception{for(String mode:List.of("success","cancel","stale","failure")){RouterOrderedLatency.reset();try(Fixture f=new Fixture(3)){
  f.connected();var target=LayeredVpnService.orderedLatencyTargets().get(0);var runner=new AndroidOrderedLatencyBenchmark();Outcome result=new Outcome();RouterOrderedLatency.mtuOccupied=true;RouterOrderedLatency.quiesceEntered=new CountDownLatch(1);RouterOrderedLatency.quiesceRelease=new CountDownLatch(1);
  runner.run(target,result);check(RouterOrderedLatency.quiesceEntered.await(5,TimeUnit.SECONDS),"MTU did not drain before facade capture");check(RouterOrderedLatency.latest==null&&AndroidMTUMeasurementGate.held(),"facade attached before original MTU joined");
  if(mode.equals("cancel"))runner.cancel();if(mode.equals("stale"))f.source.valid=false;if(mode.equals("failure"))RouterOrderedLatency.fault="quiesce";
  RouterOrderedLatency.quiesceRelease.countDown();result.joined();if(mode.equals("success"))check(result.error==null&&result.record!=null,"joined MTU could not admit original target");else check(result.error!=null&&RouterOrderedLatency.latest==null&&saved(f,target)==null,"cancelled, stale or failed MTU wait attached a facade");
  check(!AndroidMTUMeasurementGate.held(),"MTU wait leaked benchmark hold");f.source.valid=true;f.stop();
 }}}
 static void retirement()throws Exception{RouterOrderedLatency.reset();try(Fixture f=new Fixture(3)){
  f.connected();var target=LayeredVpnService.orderedLatencyTargets().get(0);var owner=LayeredVpnService.captureOrderedLatency("d".repeat(32),target);owner.start();var facade=RouterOrderedLatency.latest;var plan=f.owner().capture.socks.plan;var probe=(RouterHopMeasurement)get(f.service,"hopMeasurement");
  RouterOrderedLatency.holdClose=true;check(!f.runtime.stopAndProve(),"retirement reported DOWN before facade join");check(!plan.server.closed&&probe.closes==0&&get(f.owner(),"orderedLatency")==facade,"retirement discarded facade before original join");
  RouterOrderedLatency.holdClose=false;f.stop();check(facade.closed&&probe.closes>0&&plan.nativeClosed(),"retirement did not close facade then original throughput/Box");
 }}
 static String mutate(String raw,String fault)throws Exception{org.json.JSONObject v=new org.json.JSONObject(raw),r=v.getJSONObject("result"),b=r.getJSONObject("benchmark"),d=b.getJSONObject("distribution");
  switch(fault){case "schema":v.put("schema",2);break;case "source":v.put("source_sha256","secret");break;case "generation":v.put("generation_sha256","native-session-secret");break;case "position":v.put("position",7);break;case "request":v.put("request_id","credential");break;case "time":v.put("measured_at",System.currentTimeMillis()+120000);break;case "role":r.put("role","exit");break;case "label":r.put("label","secret password=abc");break;case "secret":v.put("password","secret");break;case "extra":r.put("download",new org.json.JSONObject());break;case "kind":r.put("kind","public-path");break;case "ready":r.put("ready",false);break;case "node":r.put("node_id","other");break;case "attempts":b.put("attempts",49);break;case "failed":b.put("failed",1);break;case "typed":b.put("attempts","50");break;case "metric":b.put("measurement","icmp-ping");break;case "endpoint":b.put("endpoint","http://private-secret/");break;case "samples":d.put("samples",6);break;case "negative":d.put("min_ms",-1);break;case "order":d.put("median_ms",8);break;case "jitter":d.put("jitter_ms",8);break;case "trimmed":b.put("trimmed_mean_ms",8);break;}return v.toString();
 }
 static void storage()throws Exception{RouterOrderedLatency.reset();try(Fixture f=new Fixture(3)){
  f.connected();var target=LayeredVpnService.orderedLatencyTargets().get(0);var initial=measure(target).record;check(initial!=null,"storage baseline missing");
  for(String fault:List.of("schema","source","generation","position","request","time","role","label","secret","extra","kind","ready","node","attempts","failed","typed","metric","endpoint","samples","negative","order","jitter","trimmed"))reject(()->new AndroidOrderedLatencyStore.Record(mutate(initial.raw,fault)),"invalid native receipt accepted: "+fault);
  java.io.File file=new java.io.File(f.service.getFilesDir(),AndroidOrderedLatencyStore.FILE_NAME);byte[] before=Files.readAllBytes(file.toPath());
  var newer=new AndroidOrderedLatencyStore.Record(new org.json.JSONObject(initial.raw).put("request_id","e".repeat(32)).put("measured_at",initial.measuredAt+1).toString());
  int[] guards={0};reject(()->AndroidOrderedLatencyStore.save(f.service,newer,()->{if(++guards[0]==3)throw new IllegalStateException("cancel during readback");}),"cancelled post-write receipt adopted");check(Arrays.equals(before,Files.readAllBytes(file.toPath())),"cancelled readback did not restore exact previous bytes");
  AndroidPrivateFileStore.failWrite=true;try{reject(()->AndroidOrderedLatencyStore.save(f.service,newer,()->{}),"interrupted write adopted");}finally{AndroidPrivateFileStore.failWrite=false;}check(Arrays.equals(before,Files.readAllBytes(file.toPath())),"interrupted write changed previous history");
  byte[] concurrent=new org.json.JSONObject().put("schema",1).put("records",new org.json.JSONArray().put(newer.raw)).toString().getBytes(java.nio.charset.StandardCharsets.UTF_8);
  var ours=new AndroidOrderedLatencyStore.Record(new org.json.JSONObject(initial.raw).put("request_id","f".repeat(32)).put("measured_at",initial.measuredAt+2).toString());
  AndroidPrivateFileStore.afterWrite=()->{try{Files.write(file.toPath(),concurrent);}catch(Exception e){throw new RuntimeException(e);}};
  reject(()->AndroidOrderedLatencyStore.save(f.service,ours,()->{}),"superseded readback adopted");check(Arrays.equals(concurrent,Files.readAllBytes(file.toPath())),"rollback overwrote a newer writer");
  android.content.Context restart=new android.content.Context();restart.files=f.service.files;check(AndroidOrderedLatencyStore.load(restart,target.source,target.config,0,target.node,target.kind).raw.equals(newer.raw),"restart lost historical receipt");
  check(AndroidOrderedLatencyStore.load(restart,"f".repeat(64),target.config,0,target.node,target.kind)==null,"history crossed ordered source");check(!new String(concurrent,java.nio.charset.StandardCharsets.UTF_8).contains("private-socks-credentials"),"history persisted credentials");f.stop();
 }}
 static void staleUI()throws Exception{RouterOrderedLatency.reset();try(Fixture f=new Fixture(3)){
  f.connected();android.app.Activity activity=new android.app.Activity();activity.files=f.service.files;AndroidOrderedLatencyDialog view=new AndroidOrderedLatencyDialog(activity);view.show();android.app.AlertDialog.last.clickItem(0);var dialog=android.app.AlertDialog.last;
  RouterOrderedLatency.holdResponses=true;dialog.getButton(-1).performClick();await(()->!activity.ui.isEmpty(),"native progress never queued");var facade=RouterOrderedLatency.latest;
  ((AndroidMTUSession)get(f.service,"mtuSession")).token=7L;activity.deliver();
  String text=((android.widget.TextView)((android.widget.ScrollView)dialog.view).children.get(0)).getText().toString();check(text.contains("captured path changed"),"queued stale progress borrowed current UI");
  await(()->!AndroidMTUMeasurementGate.held(),"queued stale progress did not cancel and join");check(facade.cancels>0&&facade.closed,"queued stale UI lost original facade cleanup");view.close();f.stop();
 }}
 static void ui()throws Exception{RouterOrderedLatency.reset();try(Fixture f=new Fixture(3)){
  f.connected();android.app.Activity activity=new android.app.Activity();activity.files=f.service.files;
  AndroidOrderedLatencyDialog view=new AndroidOrderedLatencyDialog(activity);view.show();android.app.AlertDialog chooser=android.app.AlertDialog.last;check(chooser.itemsVisible()&&chooser.items.length==3,"Fifty node selection hidden by Android message");chooser.clickItem(1);
  android.app.AlertDialog dialog=android.app.AlertDialog.last;check(dialog.getButton(-1).getText().toString().contains("Fifty / Retest"),"visible Retest absent");
  RouterOrderedLatency.holdResponses=true;dialog.getButton(-1).performClick();await(()->RouterOrderedLatency.latest!=null&&RouterOrderedLatency.latest.starts>0,"UI did not call native fifty");var facade=RouterOrderedLatency.latest;activity.deliver();
  String text=((android.widget.TextView)((android.widget.ScrollView)dialog.view).children.get(0)).getText().toString();check(text.contains("after DNS, TCP and TLS")&&!dialog.getButton(-1).isEnabled(),"public timing or active Retest exclusion lost");
  RouterOrderedLatency.holdClose=true;view.close();check(facade.closeEntered.await(5,TimeUnit.SECONDS),"dismissed UI lost cleanup");check(AndroidMTUMeasurementGate.held(),"dismissed UI released MTU before native close");RouterOrderedLatency.holdClose=false;await(()->!AndroidMTUMeasurementGate.held(),"dismissed facade never joined");activity.deliver();check(!dialog.isShowing()&&saved(f,LayeredVpnService.orderedLatencyTargets().get(1))==null,"late dismissed callback saved/displayed receipt");
  RouterOrderedLatency.reset();AndroidOrderedLatencyDialog next=new AndroidOrderedLatencyDialog(activity);next.show();android.app.AlertDialog.last.clickItem(0);dialog=android.app.AlertDialog.last;dialog.getButton(-1).performClick();await(()->!AndroidMTUMeasurementGate.held(),"UI successful benchmark did not finish");activity.deliver();text=((android.widget.TextView)((android.widget.ScrollView)dialog.view).children.get(0)).getText().toString();check(text.contains("Historical ordered-node")&&text.contains("includes connection"),"private fifty/history renderer lost interval");next.close();f.stop();
 }}
 public static void main(String[] args)throws Exception{String family=args.length==0?"all":args[0];for(String name:List.of("success","faults","pending","quiesce","retirement","storage","ui","stale-ui"))if(family.equals("all")||family.equals(name)){switch(name){case "success":success();break;case "faults":faults();break;case "pending":pending();break;case "quiesce":quiesce();break;case "retirement":retirement();break;case "storage":storage();break;case "ui":ui();break;case "stale-ui":staleUI();break;}System.out.println("Ordered fifty case passed: "+name);}System.out.println("Android ordered fifty: "+checks+" checks; native/OS boundaries doubled.");}
}'''

def main():
    jar=Path(os.environ.get('ANDROID_JSON_JAR','/usr/share/java/com.android.json.jar'))
    with tempfile.TemporaryDirectory(prefix='routervpn-ordered-fifty-') as directory:
        work=Path(directory);src=work/'src';classes=work/'classes'
        for name,text in SOURCES.items():
            target=src/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_text(text)
        names=('AndroidHomeStateStore','AndroidConnectionSelection','AndroidNodeChainSOCKSCapture','AndroidNodeChainSession','AndroidNodeChainMTUPlatform','AndroidNodeChainRuntime','LayeredVpnService','AndroidOrderedLatencyStore','AndroidOrderedLatencyBenchmark','AndroidOrderedLatencyDialog','AndroidMTUMeasurementGate')
        originals={name:(JAVA/(name+'.java')).read_text() for name in names}
        for name,text in originals.items():(src/APP/(name+'.java')).write_text(text)
        (src/APP/'OrderedFiftyTest.java').write_text(HARNESS)
        subprocess.run(['javac','--release','17','-encoding','UTF-8','-proc:none','-cp',str(jar),'-d',str(classes),*map(str,src.rglob('*.java'))],check=True,timeout=60)
        subprocess.run(['java','-cp',os.pathsep.join((str(classes),str(jar))),'com.eabusham.routervpn.OrderedFiftyTest'],check=True,timeout=120)
        controls=(
          ('AndroidOrderedLatencyBenchmark','active=job;','job.owner=LayeredVpnService.captureOrderedLatency(job.id,target);active=job;','quiesce','MTU did not drain before facade capture'),
          ('AndroidNodeChainSession','capture.socks.plan,server,measurement','capture.socks.plan,server,new io.nekohasekai.libbox.RouterHopMeasurement()','success','complete benchmark not adopted'),
          ('AndroidOrderedLatencyBenchmark','job.owner.drain();break;','break;','success','complete benchmark not adopted'),
          ('AndroidOrderedLatencyBenchmark','job.owner.close();break;','break;','success','complete benchmark not adopted'),
          ('LayeredVpnService','if(mtuObservation!=null&&!mtuObservation.equals(original.mtu==null?Long.valueOf(0L):original.mtu.proofObservationToken()))','if(false)','faults','failed/stale/cancelled run adopted: mtu'),
          ('LayeredVpnService','if(nodeChainSession!=null)try{nodeChainSession.closeOrderedLatency();}','if(false)try{nodeChainSession.closeOrderedLatency();}','retirement','retirement discarded facade before original join'),
          ('AndroidOrderedLatencyDialog','try{owner.requireDelivery();output.setText','try{output.setText','stale-ui','queued stale progress borrowed current UI'),
          ('AndroidOrderedLatencyStore','integer(distribution,"samples")!=50','false','storage','invalid native receipt accepted: samples'),
          ('AndroidOrderedLatencyStore','if(file.exists()&&Arrays.equals(written,AndroidPrivateFileStore.read(file,MAX_STORE)))','if(file.exists())','storage','rollback overwrote a newer writer'),
        )
        for i,(name,old,new,family,witness) in enumerate(controls):
            assert originals[name].count(old)==1,(name,old)
            target=work/f'mutant-{i}'/(name+'.java');target.parent.mkdir();target.write_text(originals[name].replace(old,new))
            out=work/f'negative-{i}';shutil.copytree(classes,out);cp=os.pathsep.join((str(out),str(jar)))
            subprocess.run(['javac','--release','17','-proc:none','-cp',cp,'-d',str(out),str(target)],check=True,timeout=60)
            result=subprocess.run(['java','-cp',cp,'com.eabusham.routervpn.OrderedFiftyTest',family],capture_output=True,text=True,timeout=60)
            assert result.returncode!=0 and witness in result.stderr,(family,result.stdout,result.stderr)
            print('Ordered fifty causal control rejected: '+str(i)+'/'+family)
        print('Ordered fifty all eight families and nine causal controls passed')
if __name__=='__main__':main()
