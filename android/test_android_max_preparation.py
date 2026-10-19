#!/usr/bin/env python3
"""Execute MAX capture, real Go resolution, staging and cancellation handoff.

All preparation/source checks are shipping Java. Android resolver handles and
the JNI request receiver are doubled; the returned envelope is produced by the
shipping Go request/compiler from the actual captured Java DNS answer. No
public DNS, native handshake, VPN interface or device result is claimed.
"""
from pathlib import Path
import importlib.util
import os
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('max_literal_fixture', ROOT/'android/test_android_max_selection.py')
M = importlib.util.module_from_spec(spec)
spec.loader.exec_module(M)
P = M.P
P.GO = P.GO.replace('import("bytes";', 'import("context";"bytes";', 1)
P.GO = P.GO.replace('case "max-check":', 'case "max-resolve":return maxFixtureResolve(r.Config,r.Policy)\n case "max-check":', 1) + P.M.MAX_BOUNDARY.GO_TYPES
P.HARNESS = P.HARNESS[:P.HARNESS.index(' public static void main(')] + r'''
 static void reject(Attempt attempt)throws Exception{boolean failed=false;try{attempt.run();}catch(Exception expected){failed=true;}check(failed,"invalid/retired MAX ownership was adopted");}
 interface Attempt{void run()throws Exception;}
 static void waitFor(java.util.concurrent.CountDownLatch latch)throws Exception{check(latch.await(2,java.util.concurrent.TimeUnit.SECONDS),"owned boundary was not reached");}
 static final class Job{
  final java.util.concurrent.atomic.AtomicReference<Throwable> error=new java.util.concurrent.atomic.AtomicReference<>();final Thread thread;
  Job(Attempt task){thread=new Thread(()->{try{task.run();}catch(Throwable failure){error.set(failure);}},"max-fixture-worker");thread.start();}
  void done(boolean failure)throws Exception{thread.join(3000);check(!thread.isAlive(),"MAX operation did not join");if(error.get()!=null&&!failure)throw new AssertionError("MAX worker failed",error.get());check((error.get()!=null)==failure,"MAX adopted canceled/invalid operation");}
 }
 static JSONObject hostname(String mode,String layer)throws Exception{
  JSONObject b=source(mode,"home",layer),assets=b.getJSONObject("profiles").getJSONObject(mode);String name=mode.startsWith("max-tls-")?"outer-xray.json":"middle-sing-box.json";
  JSONObject graph=new JSONObject(new String(Base64.getDecoder().decode(assets.getString(name)),StandardCharsets.UTF_8));
  if(mode.startsWith("max-tls-"))graph.getJSONArray("outbounds").getJSONObject(0).getJSONObject("settings").getJSONArray("vnext").getJSONObject(0).put("address","Captured-MAX.example.");
  else graph.getJSONArray("outbounds").getJSONObject(0).put("server","Captured-MAX.example.");
  assets.put(name,Base64.getEncoder().encodeToString(graph.toString().getBytes(StandardCharsets.UTF_8)));profile(b).put("endpoint","Captured-MAX.example.");return b;
 }
 static io.nekohasekai.libbox.RouterMAXProfileRequest.State reset(){
  AndroidHomeStateStore.value=new AndroidHomeStateStore.Snapshot();AndroidHomeStateStore.emergency=false;android.os.Build.VERSION.SDK_INT=35;
  android.net.DnsResolver.next=new android.net.DnsResolver.State();
  return io.nekohasekai.libbox.RouterMAXProfileRequest.next=new io.nekohasekai.libbox.RouterMAXProfileRequest.State();
 }
 static final class Owned {
  final Context context;final JSONObject bundle;final File source;final AndroidMAXProfilePreparation.Source captured;final AndroidMAXProfilePreparation owner;
  final String mode;final byte[] original;String config,session;File folder;
  Owned(Path root,String mode,String layer)throws Exception{
   this.mode=mode;context=new Context(Files.createTempDirectory(root,"app-").toFile());bundle=hostname(mode,layer);
   source=save(Files.createTempDirectory(root,"node-"),bundle);original=Files.readAllBytes(source.toPath());
   captured=new AndroidMAXProfilePreparation.Source(source,bundle,mode);owner=AndroidMAXProfilePreparation.begin(context,captured);
   check(owner!=null&&captured.capture.requiresResolution(),"complete hostname source lost owned preparation");
  }
  void compile()throws Exception{config=owner.compile(captured);}
  void stage()throws Exception{session=java.util.UUID.randomUUID().toString();folder=Files.createTempDirectory(context.getFilesDir().toPath(),"stage-").toFile();Files.writeString(folder.toPath().resolve("sing-box.json"),config);owner.stage(folder,session,mode,config);}
  AndroidMAXProfilePreparation.Adopted claim()throws Exception{return AndroidMAXProfilePreparation.claim(context,folder,session,mode,config,owner.identity);}
  void unchanged()throws Exception{check(Arrays.equals(original,Files.readAllBytes(source.toPath())),"resolved launch overwrote saved hostname/PQ source");}
 }
 static void successes(Path root)throws Exception{
  int graphs=0;
  for(String mode:new String[]{"max-tls-wg","max-tls-awg","max-quic-wg","max-quic-awg"})for(String layer:new String[]{"off","aes-256-gcm","aes-256-gcm+xor-whitening"})for(boolean ipv6:new boolean[]{false,true}){
   var state=reset();Owned o=new Owned(root,mode,layer);
   if(ipv6)o.context.connectivity.active.answer=new java.net.InetAddress[]{java.net.InetAddress.getByAddress(new byte[]{0x20,1,0x0d,(byte)0xb8,0,0,0,0,0,0,0,0,0,0,0,17})};
   String hash=o.captured.capture.source;reject(()->AndroidNativeMAXProfile.compile(o.bundle,o.bundle.getJSONObject("profiles").getJSONObject(mode),mode));
   o.compile();o.owner.verify();o.unchanged();check(o.captured.capture.source.equals(hash),"native source identity changed after resolve");
   JSONObject graph=new JSONObject(o.config),outer=graph.getJSONArray("outbounds").getJSONObject(layer.equals("off")?1:2);
   String physical=layer.equals("off")&&mode.startsWith("max-tls-")?new JSONObject(outer.getString("config_json")).getJSONArray("outbounds").getJSONObject(0).getJSONObject("settings").getJSONArray("vnext").getJSONObject(0).getString("address"):outer.getString("server");
   check(AndroidNumericAddress.parse(physical)!=null,"complete graph retained ambient hostname lookup");
   check(physical.equals(ipv6?"2001:db8::11":"198.51.100.17"),"graph did not use exact captured physical answer");
   check(graph.getJSONArray("endpoints").getJSONObject(0).getString("type").equals("routervpn-pq"),"resolution downgraded MAX base");
   check(android.net.DnsResolver.next.network==o.context.connectivity.active,"DNS escaped captured physical Network");
   o.stage();o.owner.beforeSubmit(o.session,mode);var adopted=o.claim();
   check(adopted.current(true)&&!AndroidMAXProfilePreparation.busy()&&state.closes.get()==1,"handoff escaped native/resolver close barrier");
   check(o.folder.isDirectory(),"successful handoff deleted staged graph");o.unchanged();
   AndroidHomeStateStore.value.sessionId="changed-session";check(!adopted.current(true),"adopted MAX lost Home session identity");adopted.cancel();graphs++;
  }
  check(graphs==24,"MAX hostname IPv4/IPv6/Start Layer matrix incomplete");
 }
 static void envelopeNegatives(Path root)throws Exception{
  for(String fault:new String[]{"hash","unhealthy","owner","source","hostname","endpoint","schema","extra","files","config"}){
   var state=reset();Owned o=new Owned(root,"max-tls-wg","off");
   state.wrongHash=fault.equals("hash");state.unhealthy=fault.equals("unhealthy");
   if(!state.wrongHash&&!state.unhealthy)state.result=value->{try{JSONObject e=new JSONObject(value);switch(fault){case "owner":e.put("owner_id","foreign");break;case "source":e.put("source_sha256","0".repeat(64));break;case "hostname":e.put("hostname","another.example");break;case "endpoint":e.put("endpoint","unresolved.example");break;case "schema":e.put("schema",1.5);break;case "extra":e.put("unowned",true);break;case "files":e.put("files_json","{}");break;case "config":e.put("config_json","{}");break;}return e.toString();}catch(Exception err){throw new RuntimeException(err);}};
   reject(o::compile);o.owner.close();o.unchanged();check(!AndroidMAXProfilePreparation.busy()&&state.closes.get()==1,"invalid native reply was not closed");
  }
 }
 static void capturedFiles(Path root)throws Exception{
  for(String fault:new String[]{"file","home","network","marker","folder","config","owner","session"}){
   reset();Owned o=new Owned(root,"max-quic-awg","aes-256-gcm+xor-whitening");o.compile();o.stage();
   if(fault.equals("file")){
    long timestamp=o.source.lastModified();byte[] changed=o.original.clone();int index=new String(changed,StandardCharsets.UTF_8).indexOf("Captured-MAX.example.");check(index>=0,"source fixture changed");changed[index]=(byte)'X';Files.write(o.source.toPath(),changed);check(o.source.setLastModified(timestamp),"mtime preservation failed");check(o.captured.current(false),"same-metadata mutation did not exercise exact readback");reject(o::claim);
   }else if(fault.equals("home")){AndroidHomeStateStore.value.sessionId="replaced";reject(o::claim);}
   else if(fault.equals("network")){o.context.connectivity.active.links.privateName="replaced.example";reject(o::claim);}
   else if(fault.equals("marker")){Files.writeString(o.folder.toPath().resolve(AndroidMAXProfilePreparation.SESSION_FILE),"{}");reject(o::claim);}
   else if(fault.equals("folder")){
    File copy=Files.createTempDirectory(o.context.getFilesDir().toPath(),"copied-stage-").toFile();Files.copy(o.folder.toPath().resolve(AndroidMAXProfilePreparation.SESSION_FILE),copy.toPath().resolve(AndroidMAXProfilePreparation.SESSION_FILE));
    reject(()->AndroidMAXProfilePreparation.claim(o.context,copy,o.session,o.mode,o.config,o.owner.identity));
   }else if(fault.equals("config")){reject(()->AndroidMAXProfilePreparation.claim(o.context,o.folder,o.session,o.mode,o.config+" ",o.owner.identity));}
   else if(fault.equals("owner")){reject(()->AndroidMAXProfilePreparation.claim(o.context,o.folder,o.session,o.mode,o.config,"stale-owner"));}
   else reject(()->AndroidMAXProfilePreparation.claim(o.context,o.folder,"wrong-session",o.mode,o.config,o.owner.identity));
   o.owner.close();check(!AndroidMAXProfilePreparation.busy()&&!o.folder.exists(),"failed/cancelled preparation left an adoptable staged owner");
  }
 }
 static void lifetime(Path root)throws Exception{
  for(String boundary:new String[]{"factory","run","close","claim-stop","claim-home"}){
   var state=reset();Owned o=new Owned(root,"max-tls-awg","off");java.util.concurrent.CountDownLatch entered=new java.util.concurrent.CountDownLatch(1),release=new java.util.concurrent.CountDownLatch(1);
   Job work;
   if(boundary.equals("factory")){state.factoryEntered=entered;state.factoryRelease=release;work=new Job(o::compile);}
   else if(boundary.equals("run")){state.runEntered=entered;state.runRelease=release;work=new Job(o::compile);}
   else{state.closeEntered=entered;state.closeRelease=release;o.compile();o.stage();work=boundary.startsWith("claim")?new Job(o::claim):new Job(o.owner::close);}
   waitFor(entered);long before=System.nanoTime();
   if(boundary.equals("claim-home"))AndroidHomeStateStore.value.sessionId="retired";else o.owner.cancel();
   check(System.nanoTime()-before<250_000_000L,"MAX STOP blocked on held native operation");
   Job drain=new Job(o.owner::close);Thread.sleep(60);
   check(work.thread.isAlive()&&drain.thread.isAlive()&&AndroidMAXProfilePreparation.busy(),"MAX registry released before constructor/worker/native Close joined");
   reject(()->AndroidMAXProfilePreparation.begin(o.context,o.captured));
   release.countDown();work.done(!boundary.equals("close"));drain.done(false);check(state.closes.get()==1&&!AndroidMAXProfilePreparation.busy(),"native request close was skipped or repeated");
   reset();Owned replacement=new Owned(root,"max-tls-awg","off");replacement.compile();o.owner.cancel();replacement.owner.verify();replacement.owner.close();
  }
 }
 static void noThreads()throws Exception{
  for(int i=0;i<100;i++){boolean found=false;for(Thread t:Thread.getAllStackTraces().keySet())if(t.isAlive()&&t.getName().startsWith("routervpn-max-"))found=true;if(!found)return;Thread.sleep(10);}throw new AssertionError("MAX owner thread escaped handoff");
 }
 public static void main(String[] args)throws Exception{
  fixtures=new JSONObject(Files.readString(Path.of(System.getenv("ROUTERVPN_MAX_PROFILE_FIXTURES"))));Path root=Path.of(args[0]);
  successes(root);envelopeNegatives(root);capturedFiles(root);lifetime(root);noThreads();
  System.out.println("Android MAX owned preparation: PASS 24 real Java/Go hostname graphs, "+checks+" checks; OS/JNI handles doubled");
 }
}
'''


def main():
    with tempfile.TemporaryDirectory(prefix='android-max-prepare-fixtures-') as temp:
        fixture = Path(temp) / 'profiles.json'
        subprocess.run(['go', 'test', '-count=1', '-run', '^TestExportMAXMobileProfiles$', './internal/mobilemultihop'], cwd=ROOT, env=dict(os.environ, ROUTERVPN_MAX_PROFILE_FIXTURES=str(fixture)), check=True, timeout=90)
        old = os.environ.get('ROUTERVPN_MAX_PROFILE_FIXTURES')
        os.environ['ROUTERVPN_MAX_PROFILE_FIXTURES'] = str(fixture)
        try:
            P.run()
        finally:
            if old is None:
                os.environ.pop('ROUTERVPN_MAX_PROFILE_FIXTURES', None)
            else:
                os.environ['ROUTERVPN_MAX_PROFILE_FIXTURES'] = old


if __name__ == '__main__':
    main()
