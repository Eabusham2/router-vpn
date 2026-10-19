"""Android/JNI boundary for MAX host fixtures; compilation stays in real Go.

This module never substitutes a runnable graph. The native request receiver is
an explicit FFI double; it obtains an answer from the shipping Java DNS owner,
then runs the shipping Go capture/request/compiler on that exact answer. Native
request lifetime has its own race gate; these barriers test Java handoff races.
"""
from pathlib import Path
import importlib.util

ROOT = Path(__file__).resolve().parents[1]
JAVA = ROOT / 'android/app/src/main/java/com/eabusham/routervpn'
spec = importlib.util.spec_from_file_location('max_dns_boundary', ROOT / 'android/test_android_max_dns_owner.py')
D = importlib.util.module_from_spec(spec)
spec.loader.exec_module(D)

GO_TYPES = r'''
type maxFixtureResolver struct{ owner, answer string }
func (r *maxFixtureResolver) OwnerID()string{return r.owner}
func (r *maxFixtureResolver) Current()bool{return true}
func (r *maxFixtureResolver) Lookup(host string)(string,error){return r.answer,nil}
func (r *maxFixtureResolver) Cancel(){}
func maxFixtureResolve(config,policy string)(string,error){
 var input struct{Mode,Files,Owner,Answer string}
 if err:=json.Unmarshal([]byte(config),&input);err!=nil{return "",err}
 request,err:=mobilemultihop.NewMAXResolveRequest(context.Background(),input.Mode,input.Files,policy,&maxFixtureResolver{input.Owner,input.Answer})
 if err!=nil{return "",err};defer request.Close();return request.Run()
}
'''

LIBBOX = r'''
 public static RouterMAXProfileRequest maxRequest;
 public static RouterMAXProfileRequest routerCreateMAXProfileRequest(String mode,String files,String metadata,RouterMAXEndpointResolver resolver)throws Exception {
  RouterMAXProfileRequest value=new RouterMAXProfileRequest(mode,files,metadata,resolver);maxRequest=value;return value;
 }
 static String maxResolveForTest(String mode,String files,String metadata,RouterMAXEndpointResolver resolver,String answer)throws Exception {
  return call("max-resolve",new JSONObject().put("Mode",mode).put("Files",files).put("Owner",resolver.ownerID()).put("Answer",answer).toString(),metadata);
 }
'''

REQUEST = r'''package io.nekohasekai.libbox;
import org.json.*;import java.util.concurrent.*;import java.util.concurrent.atomic.*;
public final class RouterMAXProfileRequest {
 public static final class State {
  public CountDownLatch factoryEntered,factoryRelease,runEntered,runRelease,closeEntered,closeRelease;
  public java.util.function.UnaryOperator<String> result;
  public boolean wrongHash,unhealthy,failClose;
  public final AtomicInteger cancels=new AtomicInteger(),closes=new AtomicInteger();
 }
 public static volatile State next=new State();
 final State state;final String mode,files,metadata,source;final RouterMAXEndpointResolver resolver;
 final CountDownLatch done=new CountDownLatch(1);final AtomicBoolean started=new AtomicBoolean();
 volatile boolean cancelled,succeeded;
 public RouterMAXProfileRequest(String m,String f,String p,RouterMAXEndpointResolver r)throws Exception {
  state=next;mode=m;files=f;metadata=p;resolver=r;source=Libbox.routerCheckMAXProfile(m,f,p);
  if(state.factoryEntered!=null)state.factoryEntered.countDown();hold(state.factoryRelease);
 }
 static void hold(CountDownLatch latch){if(latch==null)return;boolean interrupted=false;for(;;){try{latch.await();break;}catch(InterruptedException e){interrupted=true;}}if(interrupted)Thread.currentThread().interrupt();}
 public String sourceSHA256(){return state.wrongHash?"0".repeat(64):source;}
 public String run()throws Exception {
  if(!started.compareAndSet(false,true))throw new IllegalStateException("already used");
  try {
   if(cancelled||!resolver.current())throw new IllegalStateException("retired");
   if(state.runEntered!=null)state.runEntered.countDown();hold(state.runRelease);
   if(cancelled||!resolver.current())throw new IllegalStateException("retired");
   String answer=resolver.lookup(new JSONObject(metadata).getString("endpoint"));
   String value=Libbox.maxResolveForTest(mode,files,metadata,resolver,answer);
   if(cancelled||!resolver.current())throw new IllegalStateException("retired");
   succeeded=true;return state.result==null?value:state.result.apply(value);
  }finally{done.countDown();}
 }
 public boolean healthy(){return succeeded&&!cancelled&&!state.unhealthy&&resolver.current();}
 public void cancel(){if(!cancelled){cancelled=true;succeeded=false;state.cancels.incrementAndGet();}resolver.cancel();}
 public void close()throws Exception {
  cancel();if(started.get())hold(done);if(state.closeEntered!=null)state.closeEntered.countDown();hold(state.closeRelease);state.closes.incrementAndGet();
  if(state.failClose)throw new IllegalStateException("boundary cleanup failed");
 }
}
'''

APP_BOUNDARY = r'''package com.eabusham.routervpn;
final class AndroidPrivateFileStore {
 static String failName;
 static byte[] read(java.io.File file,int maximum)throws Exception{
  if(file==null||!java.nio.file.Files.isRegularFile(file.toPath(),java.nio.file.LinkOption.NOFOLLOW_LINKS)||java.nio.file.Files.size(file.toPath())<=0||java.nio.file.Files.size(file.toPath())>maximum)throw new java.io.IOException("Invalid bounded private fixture");
  return java.nio.file.Files.readAllBytes(file.toPath());
 }
 static void write(java.io.File file,byte[] data,int maximum)throws Exception{
  if(file.getName().equals(failName))throw new java.io.IOException("Injected private staging failure");
  if(data==null||data.length==0||data.length>maximum)throw new java.io.IOException("Invalid bounded private fixture");
  java.nio.file.Files.createDirectories(file.toPath().getParent());java.nio.file.Files.write(file.toPath(),data);
 }
}
final class AndroidHomeStateStore {
 static final class Snapshot{boolean connected;String phase="idle",sessionId="home-capture";}
 static volatile Snapshot value=new Snapshot();static volatile boolean emergency;
 static Snapshot snapshot(android.content.Context c){return value;}
 static boolean emergencyDisconnectPending(android.content.Context c){return emergency;}
}
'''


def install(stubs):
    for name, source in D.STUBS.items():
        if name not in ('android/content/Context.java', 'android/os/Build.java'):
            stubs[name] = source
    name = 'android/content/Context.java'
    stubs[name] = stubs[name].replace(' public Context getApplicationContext()', '''
 public static final String CONNECTIVITY_SERVICE="connectivity";
 public final android.net.ConnectivityManager connectivity=new android.net.ConnectivityManager();
 public Object getSystemService(String service){return connectivity;}
 public Context getApplicationContext()''', 1)
    name = 'com/eabusham/routervpn/Boundaries.java'
    stubs[name] = stubs[name].replace('final class AndroidNodeStore {', 'final class AndroidNodeStore {\n static final int MAX_BUNDLE=64*1024*1024;', 1)
    home = APP_BOUNDARY.index('final class AndroidHomeStateStore {')
    stubs['com/eabusham/routervpn/MAXBoundary.java'] = APP_BOUNDARY[:home]
    # A test which owns the full Home store can replace this exact source path.
    stubs['com/eabusham/routervpn/AndroidHomeStateStore.java'] = 'package com.eabusham.routervpn;\n' + APP_BOUNDARY[home:]
    for name in ('AndroidMAXDNSOwner', 'AndroidMAXProfilePreparation'):
        stubs['com/eabusham/routervpn/' + name + '.java'] = (JAVA / (name + '.java')).read_text()
    name = 'io/nekohasekai/libbox/Libbox.java'
    anchor = ' public static String routerMAXMultihopBase('
    assert stubs[name].count(anchor) == 1
    stubs[name] = stubs[name].replace(anchor, LIBBOX + anchor, 1)
    stubs['io/nekohasekai/libbox/RouterMAXProfileRequest.java'] = REQUEST
