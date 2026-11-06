#!/usr/bin/env python3
"""Actual Router DNS callbacks, request I/O and node-store transactions.

Android widgets, Libbox source admission and private-file platform calls are
explicit boundaries. Real loopback TCP serves the shipping HTTP request; this
is not device routing or selected-DNS native proof.
"""
from pathlib import Path
import importlib.util
import os
import shutil
import subprocess
import tempfile

ROOT=Path(__file__).resolve().parents[1]
JAVA=ROOT/'android/app/src/main/java/com/eabusham/routervpn'
def load(name,file):
    spec=importlib.util.spec_from_file_location(name,ROOT/'android'/file)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
W=load('retest_widgets','test_android_tor_form.py')
P=load('retest_store','test_android_connection_profiles.py')
def method(source,signature):
    start=source.index(signature);brace=source.index('{',start);depth=1;end=brace+1
    while depth:
        if source[end]=='{':depth+=1
        elif source[end]=='}':depth-=1
        end+=1
    return source[start:end]

BOUNDARIES=r'''package com.eabusham.routervpn;
import java.io.*;import java.nio.file.*;
'''+P.BOUNDARIES.split('final class AndroidPrivateFileStore {',1)[1].split('final class AndroidStartupPolicy',1)[0].join(['final class AndroidPrivateFileStore {',''])+r'''
final class AndroidVpnMutationGuard {static boolean busy;static boolean isBusy(android.content.Context c){return busy;}}
final class AndroidNativeProfilePolicy {
 static final class HomeDNS {String host="10.0.0.53",protocol="udp",serverName="",path="";int port=53;void apply(org.json.JSONObject p){throw new AssertionError("Home editor boundary");}}
 static HomeDNS homeDNS(org.json.JSONObject p,Object... args){return new HomeDNS();}
 static String stringPolicy(org.json.JSONObject p,String k,String d){return p.optString(k,d);}
}
'''
HARNESS=r'''package com.eabusham.routervpn;
import android.app.*;import android.widget.*;import android.view.*;import org.json.*;
import java.io.*;import java.net.*;import java.nio.charset.StandardCharsets;import java.nio.file.*;import java.util.*;import java.util.concurrent.*;
public final class RouterDNSRetestHarness {
 static int checks;
 static void check(boolean value,String reason){checks++;if(!value)throw new AssertionError(reason);}
 static void await(CountDownLatch latch)throws Exception{check(latch.await(5,TimeUnit.SECONDS),"bounded witness missing");}
 interface Action{void run()throws Exception;}
 static void reject(Action action,String message)throws Exception{boolean rejected=false;try{action.run();}catch(Exception expected){rejected=true;}check(rejected,message);}
 static byte[] bytes(JSONObject o){return o.toString().getBytes(StandardCharsets.UTF_8);}
 static JSONObject node(char identity,int port)throws Exception{return new JSONObject().put("nodeProofId",String.valueOf(identity).repeat(64)).put("selectedRouterID","same-profile").put("profiles",new JSONObject().put("wg",new JSONObject().put("fixture","private-reference"))).put("modes",new JSONArray()).put("routerProfiles",new JSONArray().put(new JSONObject().put("id","same-profile").put("name","fixture").put("router_api","http://127.0.0.1:"+port).put("api_token","fixture-only-token").put("dns_mode","custom").put("dns_host","9.9.9.9")));}
 static JSONObject result()throws Exception{return new JSONObject().put("results",new JSONArray().put(new JSONObject().put("address","1.1.1.1").put("working",true).put("latency_ms",3))).put("winner",new JSONObject().put("address","1.1.1.1").put("name","fixture DNS").put("latency_ms",3));}
 static final class Fixture {
  final Activity activity;final AndroidNodeStore store,other;final AndroidNodeStore.Node first,second;
  Fixture(Path dir,int port)throws Exception{activity=new Activity(Files.createTempDirectory(dir,"app-").toFile());store=new AndroidNodeStore(activity);other=new AndroidNodeStore(activity);first=store.importBundle(bytes(node('a',port)));second=store.importBundle(bytes(node('b',port)));store.select(first.id);}
  String text(AndroidNodeStore.Node n)throws Exception{return Files.readString(n.file.toPath());}
  void open(){AndroidProductParity.showDNS(activity,store);check(AlertDialog.last!=null&&AlertDialog.last.isShowing(),"shipping DNS dialog did not show");}
 }
 static <T> List<T> views(View root,Class<T> type){List<T> found=new ArrayList<>();if(type.isInstance(root))found.add(type.cast(root));if(root instanceof LinearLayout)for(View child:((LinearLayout)root).children)found.addAll(views(child,type));return found;}
 static Button button(String label){for(Button b:views(AlertDialog.last.view,Button.class))if(b.getText().toString().equals(label))return b;throw new AssertionError("missing "+label);}
 static TextView output(){for(TextView t:views(AlertDialog.last.view,TextView.class))if(t.getText().toString().contains("RTT = median"))return t;throw new AssertionError("missing benchmark");}
 static final class Server implements AutoCloseable {
  final ServerSocket server=new ServerSocket(0,8,InetAddress.getLoopbackAddress());final CountDownLatch received=new CountDownLatch(1),reply=new CountDownLatch(1),ended=new CountDownLatch(1);volatile Throwable failure;volatile boolean eof;final Thread thread;
  Server(boolean respond)throws Exception{thread=new Thread(()->{try(Socket socket=server.accept()){socket.setSoTimeout(5000);InputStream in=socket.getInputStream();ByteArrayOutputStream request=new ByteArrayOutputStream();int c;while((c=in.read())!=-1){request.write(c);String s=request.toString(StandardCharsets.US_ASCII);if(s.endsWith("\r\n\r\n{}")){if(!s.startsWith("POST /api/dns/benchmark HTTP/1.1")||!s.contains("Authorization: Bearer fixture-only-token"))throw new AssertionError("shipping HTTP changed captured credentials/path");break;}}received.countDown();if(respond){await(reply);byte[] body=bytes(result());socket.getOutputStream().write(("HTTP/1.1 200 OK\r\nContent-Length: "+body.length+"\r\n\r\n").getBytes(StandardCharsets.US_ASCII));socket.getOutputStream().write(body);}else eof=in.read()==-1;}catch(Throwable error){failure=error;}finally{received.countDown();ended.countDown();}},"fixture-private-http");thread.start();}
  public void close()throws Exception{reply.countDown();server.close();thread.join(6000);check(!thread.isAlive(),"fixture server not joined");if(failure!=null)throw new AssertionError("fixture server failed",failure);}
 }
 static void dispatch(Activity a)throws Exception{Runnable r=a.events.poll(5,TimeUnit.SECONDS);check(r!=null,"missing joined UI callback");r.run();}
 static byte[] resultBytes(AndroidNodeStore.SelectionSnapshot source)throws Exception{JSONObject b=new JSONObject(new String(source.activeBundle,StandardCharsets.UTF_8));b.getJSONArray("routerProfiles").getJSONObject(0).put("dns_results",result().getJSONArray("results"));return bytes(b);}
 static void storeCases(Path root)throws Exception{
  Fixture f=new Fixture(root,9);var captured=f.store.snapshotSelection();byte[] update=resultBytes(captured);String original=f.text(f.first),other=f.text(f.second);
  f.other.select(f.second.id);reject(()->f.store.applyDNSBenchmark(captured,update),"same-profile foreign node accepted old result");check(other.equals(f.text(f.second)),"foreign node received result");
  f.other.select(f.first.id);reject(()->f.store.applyDNSBenchmark(captured,update),"away-and-back accepted old result");
  var same=f.store.snapshotSelection();f.other.importBundle(same.activeBundle);reject(()->f.store.applyDNSBenchmark(same,resultBytes(same)),"byte-identical source replacement accepted old result");
  var failed=f.store.snapshotSelection();f.activity.getSharedPreferences("router-vpn",0).failures=1;reject(()->f.other.importBundle(bytes(node('a',10))),"injected write did not fail");check(original.equals(f.text(f.first)),"rollback did not preserve original source");reject(()->f.store.applyDNSBenchmark(failed,resultBytes(failed)),"failed publication and rollback revived capture");
  Fixture broken=new Fixture(root,9);var beforeBroken=broken.store.snapshotSelection();var prefs=broken.activity.getSharedPreferences("router-vpn",0);prefs.failures=1;prefs.beforeFailure=()->AndroidPrivateFileStore.beforeWrite=()->{throw new IllegalStateException("fixture rollback unavailable");};
  try{reject(()->broken.other.importBundle(bytes(node('a',10))),"rollback failure was hidden");reject(()->broken.store.requireDNSBenchmarkSource(beforeBroken),"incomplete rollback revived old capture");}finally{AndroidPrivateFileStore.beforeWrite=null;}
  var live=f.store.snapshotSelection();AndroidVpnMutationGuard.busy=true;reject(()->f.store.applyDNSBenchmark(live,resultBytes(live)),"measurement bypassed busy policy guard");AndroidVpnMutationGuard.busy=false;check(original.equals(f.text(f.first)),"busy result mutated source");
  var adopted=f.store.applyDNSBenchmark(live,resultBytes(live));f.store.requireDNSBenchmarkSource(adopted);check(!original.equals(f.text(f.first)),"valid result not persisted");
  // Hold the real publication boundary while an independent store tries to select.
  var atomic=f.store.snapshotSelection();CountDownLatch atWrite=new CountDownLatch(1),release=new CountDownLatch(1),selectEntered=new CountDownLatch(1);Throwable[] errors=new Throwable[2];
  AndroidNodeStore.dnsChecked=()->{AndroidNodeStore.dnsChecked=null;atWrite.countDown();try{await(release);}catch(Exception e){throw new RuntimeException(e);}};
  Thread writer=new Thread(()->{try{f.store.applyDNSBenchmark(atomic,resultBytes(atomic));}catch(Throwable e){errors[0]=e;}});Thread selector=new Thread(()->{selectEntered.countDown();try{f.other.select(f.second.id);}catch(Throwable e){errors[1]=e;}});
  writer.start();await(atWrite);selector.start();await(selectEntered);try{long until=System.nanoTime()+TimeUnit.SECONDS.toNanos(3);while(selector.getState()!=Thread.State.BLOCKED&&selector.isAlive()&&System.nanoTime()<until)Thread.yield();check(selector.getState()==Thread.State.BLOCKED,"store selection escaped atomic compare/publication");}finally{release.countDown();writer.join(5000);selector.join(5000);}check(!writer.isAlive()&&!selector.isAlive()&&errors[0]==null&&errors[1]==null,"store operations did not join");check(f.store.activeId().equals(f.second.id)&&other.equals(f.text(f.second)),"result overwrote concurrent selection");
 }
 static void ownership(Path root)throws Exception{
  Fixture f=new Fixture(root,9);AndroidRouterDNSRetest owner=new AndroidRouterDNSRetest();CountDownLatch entered=new CountDownLatch(1),release=new CountDownLatch(1),completed=new CountDownLatch(1);var capture=f.store.snapshotSelection();
  var job=owner.start(f.store,capture,io->{entered.countDown();while(release.getCount()>0)try{release.await();}catch(InterruptedException ignored){}return result();},(j,r,e)->{check(j.joined&&!j.worker.isAlive(),"callback preceded actual worker join");completed.countDown();});await(entered);owner.cancel();
  reject(()->new AndroidRouterDNSRetest().start(f.store,capture,io->result(),(j,r,e)->{}),"cancel released running owner");release.countDown();await(completed);reject(()->owner.adopt(job,()->{throw new AssertionError("cancelled adoption executed");}),"cancelled result adopted");owner.close();
 }
 static void replacement(Path root)throws Exception{
  Fixture f=new Fixture(root,9);var source=f.store.snapshotSelection();AndroidRouterDNSRetest old=new AndroidRouterDNSRetest(),next=new AndroidRouterDNSRetest();CountDownLatch oldDone=new CountDownLatch(1),nextEntered=new CountDownLatch(1),release=new CountDownLatch(1),nextDone=new CountDownLatch(1);String original=f.text(f.first);
  var first=old.start(f.store,source,io->result(),(j,r,e)->oldDone.countDown());await(oldDone);
  var second=next.start(f.store,source,io->{nextEntered.countDown();release.await();return result();},(j,r,e)->nextDone.countDown());await(nextEntered);
  try{reject(()->old.adopt(first,()->f.store.applyDNSBenchmark(source,resultBytes(source))),"old panel persisted over newer measurement");check(original.equals(f.text(f.first)),"delayed prior panel changed source");old.close();check(!second.cancelled,"old close cancelled replacement owner");}finally{release.countDown();await(nextDone);}next.adopt(second,()->f.store.applyDNSBenchmark(source,resultBytes(source)));check(f.text(f.first).contains("dns_results"),"replacement result did not adopt");next.close();
 }
 static void uiCases(Path root)throws Exception{
  for(String action:new String[]{"success","cancel","dismiss","switch","away-back","source","busy"})try(Server server=new Server(!action.equals("cancel")&&!action.equals("dismiss")&&!action.equals("switch"))){
   Fixture f=new Fixture(root,server.server.getLocalPort());String first=f.text(f.first),second=f.text(f.second);f.open();AlertDialog dialog=AlertDialog.last;TextView output=output();button("Retest DNS RTT from home node").performClick();await(server.received);
   if(action.equals("cancel"))button("Cancel DNS Retest").performClick();
   else if(action.equals("dismiss"))dialog.dismiss();
   else if(action.equals("switch"))f.other.select(f.second.id);
   else {server.reply.countDown();await(server.ended);Runnable callback=f.activity.events.poll(5,TimeUnit.SECONDS);check(callback!=null,"result callback absent");
    if(action.equals("away-back")){f.other.select(f.second.id);f.other.select(f.first.id);}
    if(action.equals("source"))f.other.importBundle(bytes(node('a',server.server.getLocalPort())));
    if(action.equals("busy"))AndroidVpnMutationGuard.busy=true;
    callback.run();AndroidVpnMutationGuard.busy=false;
   }
   if(action.equals("cancel")||action.equals("dismiss")||action.equals("switch")){check(server.ended.await(6,TimeUnit.SECONDS)&&server.eof,"cancel did not close original HTTP socket");String before=output.getText().toString();dispatch(f.activity);if(action.equals("dismiss"))check(before.equals(output.getText().toString()),"dismissed UI accepted callback");}
   if(action.equals("success")){check(f.text(f.first).contains("dns_results"),"successful callback did not persist");check(output.getText().toString().contains("Fastest measured"),"successful callback did not render");check(f.text(f.first).contains("9.9.9.9"),"Retest rewrote selected DNS policy");}
   else {check(first.equals(f.text(f.first))&&second.equals(f.text(f.second)),"stale/cancelled callback changed node source: "+action);if(action.equals("busy"))check(output.getText().toString().contains("completed, but results were not saved"),"busy completed query misrepresented");}
   dialog.dismiss();
  }
 }
 public static void main(String[] args)throws Exception{Path root=Path.of(args[0]);storeCases(root);ownership(root);replacement(root);uiCases(root);System.out.println("Router home DNS Retest: "+checks+" checks passed (actual callbacks, TCP request, store; Android/platform validation boundaries doubled)");}
}
'''

def main():
    jar=Path(os.environ.get('ANDROID_JSON_JAR','/usr/share/java/com.android.json.jar'))
    if not jar.is_file():raise RuntimeError('Real Android JSON required')
    with tempfile.TemporaryDirectory(prefix='router-dns-retest-') as directory:
        work=Path(directory);src=work/'src';stubs=dict(W.UI)
        stubs.update({k:v for k,v in P.STUBS.items() if k in ('android/content/SharedPreferences.java','android/content/Context.java','android/content/MemoryPreferences.java','android/util/Base64.java')})
        stubs['android/content/Context.java']=stubs['android/content/Context.java'].replace('public Context(java.io.File files)', 'public android.content.res.Resources getResources(){return new android.content.res.Resources();} public Object startService(Intent i){return null;} public Object startForegroundService(Intent i){return null;} public Context(java.io.File files)')
        stubs['android/app/Activity.java']='''package android.app;public class Activity extends android.content.Context {public boolean finishing;public final java.util.concurrent.BlockingQueue<Runnable> events=new java.util.concurrent.LinkedBlockingQueue<>();public Activity(java.io.File f){super(f);}public boolean isFinishing(){return finishing;}public void runOnUiThread(Runnable r){events.add(r);}}'''
        stubs['android/widget/ArrayAdapter.java']=stubs['android/widget/ArrayAdapter.java'].replace('public void setDropDownViewResource', 'public ArrayAdapter(android.content.Context c,int layout,java.util.List<T> source){values=(T[])source.toArray();} public void setDropDownViewResource')
        stubs['android/widget/Spinner.java']=stubs['android/widget/Spinner.java'].replace('public int getSelectedItemPosition()', 'public Object getSelectedItem(){return adapter.getItem(position);}public int getSelectedItemPosition()')
        stubs['android/app/AlertDialog.java']=stubs['android/app/AlertDialog.java'].replace('BUTTON_NEGATIVE=-2','BUTTON_NEGATIVE=-2,BUTTON_NEUTRAL=-3').replace('public void show(){','public boolean isShowing(){return showing;}public void show(){').replace('else if(which==BUTTON_NEGATIVE)', 'else if(which==BUTTON_NEGATIVE||which==BUTTON_NEUTRAL)').replace('public Builder setNegativeButton', 'public Builder setNeutralButton(CharSequence t,OnClickListener l){return button(BUTTON_NEUTRAL,t,l);}public Builder setNegativeButton')
        stubs['io/nekohasekai/libbox/Libbox.java']='package io.nekohasekai.libbox;public final class Libbox {public static void routerValidatePrivateNodeJSON(String s)throws Exception{new org.json.JSONObject(s);}}'
        for name,content in stubs.items():
            target=src/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_text(content)
        app=src/'com/eabusham/routervpn';app.mkdir(parents=True)
        for name in ('AndroidNodeStore','AndroidProfileSelection','AndroidTelemetryIO','AndroidRouterDNSRetest'):
            shutil.copyfile(JAVA/(name+'.java'),app/(name+'.java'))
        # Observe the actual source-check/publication boundary without changing
        # shipping code; this exact hook is only in the disposable Java projection.
        store=app/'AndroidNodeStore.java';source=store.read_text()
        anchor='        requireDNSBenchmarkSource(source);\n        // Shared writer lock'
        if source.count(anchor)!=1:raise AssertionError('DNS transaction witness anchor changed')
        source=source.replace('private static long selectionGeneration;', 'private static long selectionGeneration; static Runnable dnsChecked;')
        source=source.replace(anchor,'        requireDNSBenchmarkSource(source);\n        if(dnsChecked!=null)dnsChecked.run();\n        // Shared writer lock',1)
        store.write_text(source)
        parity=(JAVA/'AndroidProductParity.java').read_text();parity=parity.replace(method(parity,'    static void showModes('),'')
        (app/'AndroidProductParity.java').write_text(parity)
        (app/'Boundaries.java').write_text(BOUNDARIES)
        (app/'RouterDNSRetestHarness.java').write_text(HARNESS)
        classes=work/'classes';data=work/'data';data.mkdir()
        subprocess.run(['javac','--release','17','-encoding','UTF-8','-cp',str(jar),'-d',str(classes),*map(str,src.rglob('*.java'))],check=True,timeout=60)
        subprocess.run(['java','-cp',str(classes)+os.pathsep+str(jar),'com.eabusham.routervpn.RouterDNSRetestHarness',str(data)],check=True,timeout=60)
        controls=(
            ('atomic','AndroidNodeStore','synchronized SelectionSnapshot applyDNSBenchmark(SelectionSnapshot source, byte[] updated) throws Exception { synchronized (STORE_LOCK) {','synchronized SelectionSnapshot applyDNSBenchmark(SelectionSnapshot source, byte[] updated) throws Exception { synchronized (new Object()) {','store selection escaped atomic compare/publication'),
            ('generation','AndroidNodeStore','source.generation != selectionGeneration || ','','away-and-back accepted old result'),
            ('latest','AndroidRouterDNSRetest','latestIdentity != job.identity || ','','old panel persisted over newer measurement'),
            ('dismiss','AndroidProductParity','dialog.setOnDismissListener(x->measurement.close());','','cancel did not close original HTTP socket'),
            ('cancel','AndroidRouterDNSRetest','current.cancelled = true; current.io.cancel();','current.cancelled = true;','cancel did not close original HTTP socket'),
        )
        for label,owner,before,after,diagnostic in controls:
            original=(app/(owner+'.java')).read_text()
            if original.count(before)!=1:raise AssertionError('causal mutation anchor changed: '+label)
            negative=work/('negative-'+label);negative.mkdir();changed=negative/(owner+'.java');changed.write_text(original.replace(before,after,1))
            subprocess.run(['javac','--release','17','-encoding','UTF-8','-cp',str(classes)+os.pathsep+str(jar),'-d',str(negative),str(changed)],check=True,timeout=60)
            observed=subprocess.run(['java','-cp',str(negative)+os.pathsep+str(classes)+os.pathsep+str(jar),'com.eabusham.routervpn.RouterDNSRetestHarness',str(data)],text=True,capture_output=True,timeout=60)
            if observed.returncode==0 or diagnostic not in observed.stdout+observed.stderr:
                raise AssertionError('causal control did not reach expected rejection: '+label+'\n'+observed.stdout+observed.stderr)
            print('Rejected Router DNS Retest mutation: '+label)

if __name__=='__main__':main()
