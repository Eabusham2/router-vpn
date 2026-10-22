#!/usr/bin/env python3
"""Execute the shipping via-entry measurement, proof, IO and WG ownership classes.

Android network handles and WireGuard's OS backend are deterministic doubles.
The ordinary startup proof uses a real loopback HTTP server. Candidate sockets
exist only on the captured Network double: .invalid names cannot use host DNS.
This is lifecycle/routing-boundary coverage, not physical Android VPN evidence.
"""
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
JAVA = ROOT / "android/app/src/main/java/com/eabusham/routervpn"
CLASSES = ("NativeWireGuardController", "AndroidPathProbe", "AndroidViaEntryProbeIO",
           "AndroidViaEntryPathMeter", "AndroidViaEntryLatencyProbe")
SOURCES = {
"android/content/Context.java": '''package android.content;
public class Context {public static final String CONNECTIVITY_SERVICE="connectivity";
 public final android.net.ConnectivityManager network=new android.net.ConnectivityManager();
 public Context getApplicationContext(){return this;}public Object getSystemService(String name){return network;}}
''',
"android/net/ConnectivityManager.java": '''package android.net;
public class ConnectivityManager {public volatile Network active;public Network idle,vpn;
 public Network getActiveNetwork(){return active;}
 public NetworkCapabilities getNetworkCapabilities(Network network){return network==null?null:new NetworkCapabilities(network.vpn);}}
''',
"android/net/NetworkCapabilities.java": '''package android.net;
public class NetworkCapabilities {public static final int TRANSPORT_VPN=4;final boolean vpn;public static int uid=1000;
 public NetworkCapabilities(boolean vpn){this.vpn=vpn;}public boolean hasTransport(int kind){return vpn;}public int getOwnerUid(){if(android.os.Build.VERSION.SDK_INT<30)throw new NoSuchMethodError("getOwnerUid requires API30");return uid;}}
''',
"android/net/Network.java": '''package android.net;
public class Network {public interface Resolver {java.net.InetAddress[] resolve(String host)throws java.net.UnknownHostException;}
 public final boolean vpn;public final Resolver resolver;public final javax.net.SocketFactory sockets;
 public Network(boolean vpn,Resolver resolver,javax.net.SocketFactory sockets){this.vpn=vpn;this.resolver=resolver;this.sockets=sockets;}
 public java.net.InetAddress[] getAllByName(String host)throws java.net.UnknownHostException{return resolver.resolve(host);}
 public javax.net.SocketFactory getSocketFactory(){return sockets;}}
''',
"android/os/Build.java": "package android.os;public class Build {public static class VERSION {public static int SDK_INT=35;}public static class VERSION_CODES {public static final int Q=29,R=30;}}",
"android/os/Process.java": "package android.os;public class Process {public static int myUid(){return 1000;}}",
"android/util/Base64.java": "package android.util;public class Base64 {public static final int DEFAULT=0;public static byte[] decode(String value,int flags){return java.util.Base64.getDecoder().decode(value);}}",
"com/wireguard/android/backend/Tunnel.java": "package com.wireguard.android.backend;public interface Tunnel {enum State {UP,DOWN}String getName();void onStateChange(State state);}",
"com/wireguard/config/Config.java": "package com.wireguard.config;public class Config {public static Config parse(java.io.InputStream source)throws Exception{if(source.readAllBytes().length==0)throw new IllegalStateException();return new Config();}}",
"com/wireguard/android/backend/GoBackend.java": '''package com.wireguard.android.backend;
import android.content.Context;import java.util.concurrent.*;import java.util.concurrent.atomic.*;
public final class GoBackend {
 public static final AtomicInteger ups=new AtomicInteger(),downs=new AtomicInteger(),failDown=new AtomicInteger();
 public static volatile Runnable beforeDown;public static volatile CountDownLatch enteredDown,releaseDown;
 final Context context;public GoBackend(Context context){this.context=context;}
 public Tunnel.State setState(Tunnel tunnel,Tunnel.State state,com.wireguard.config.Config config)throws Exception {
  if(state==Tunnel.State.UP){ups.incrementAndGet();context.network.active=context.network.vpn;}
  else {downs.incrementAndGet();if(beforeDown!=null){Runnable once=beforeDown;beforeDown=null;once.run();}
   if(enteredDown!=null){enteredDown.countDown();releaseDown.await();}
   if(failDown.getAndUpdate(value->Math.max(0,value-1))>0)return Tunnel.State.UP;
   context.network.active=context.network.idle;}
  tunnel.onStateChange(state);return state;
 }
 public static void reset(){ups.set(0);downs.set(0);failDown.set(0);beforeDown=null;enteredDown=null;releaseDown=null;}
}
''',
"com/eabusham/routervpn/ProbeBoundaries.java": r'''package com.eabusham.routervpn;
import android.content.Context;import java.io.*;import java.nio.file.*;import org.json.JSONObject;
final class AndroidNodeStore {
 static final int MAX_NODES=24,MAX_BUNDLE=32*1024*1024;
 static final class Node {final String id,name,endpoint;final File file;Node(String id,File file){this.id=id;this.name=id;this.file=file;endpoint="candidate-"+id+".invalid";}}
 static void validateBundle(JSONObject value){if(value.optString("node_id").isEmpty())throw new IllegalArgumentException("missing node");}
 static String stableNodeIdentity(JSONObject value){return value.optString("node_id");}
}
final class AndroidPrivateFileStore {static byte[] read(File file,int max)throws Exception{byte[] bytes=Files.readAllBytes(file.toPath());if(bytes.length==0||bytes.length>max)throw new IOException("size");return bytes;}}
final class AndroidProfileSelection {static JSONObject selectedRouterProfile(JSONObject root){return root.optJSONObject("profile");}}
final class AndroidNativeProfilePolicy {static String patchWireGuardLikeConfig(JSONObject root,String raw,int mtu){return raw;}}
final class AndroidKillSwitchPolicy {static boolean strictRequested(File file){return false;}static String requirementMessage(){return "strict";}}
final class AndroidUnderlyingNetworkMonitor {
 static volatile Runnable change;AndroidUnderlyingNetworkMonitor(Context context){}
 void start(Runnable listener){change=listener;}void stop(){change=null;}
}
final class AndroidHomeStateStore {
 static final class Snapshot {String sessionId="",phase="off",activeNodeId="",activeEntryId="",activeExitId="";long pathGeneration;}
 static volatile Snapshot state=new Snapshot();static Snapshot snapshot(Context context){return state;}
 static String nodeIdFromBundleFile(File file){return file.getName();}
 static void begin(Context c,String a,String b,String d,String node){state=new Snapshot();state.sessionId="replacement";state.phase="connecting";}
 static void connected(Context c,String a,String b,String d,String e,String node){state.phase="connected";}
 static Snapshot beginPathRevalidation(Context context,String reason){return null;}
 static boolean completePathRevalidation(Context c,Snapshot capture){return true;}
 static boolean emergencyDisconnectPending(Context c){return false;}
 static void disconnected(Context c){state=new Snapshot();}static void failed(Context c,String text){state.phase="failed";}static void warning(Context c,String text){}
}
final class AndroidRuntimeRegistry {final NativeWireGuardController wireGuard;AndroidRuntimeRegistry(Context context){wireGuard=new NativeWireGuardController(context);}}
final class AndroidVpnMutationGuard {static boolean busy;static boolean isBusy(Context context){return busy||AndroidViaEntryLatencyProbe.hasActiveOperation();}}
final class AndroidTelemetry {static final class Result {
 final String id,name;final double minMs,medianMs,meanMs,p90Ms,maxMs;final int samples,failed;
 Result(String id,String name,double min,double median,double mean,double p90,double max,int samples,int failed){this.id=id;this.name=name;minMs=min;medianMs=median;meanMs=mean;p90Ms=p90;maxMs=max;this.samples=samples;this.failed=failed;}
}}
''',
"com/eabusham/routervpn/ViaEntryHarness.java": r'''package com.eabusham.routervpn;
import android.content.Context;import android.net.*;import com.wireguard.android.backend.*;
import java.io.*;import java.net.*;import java.nio.charset.StandardCharsets;import java.nio.file.*;
import java.util.*;import java.util.concurrent.*;import java.util.concurrent.atomic.*;import javax.net.SocketFactory;import org.json.JSONObject;
public final class ViaEntryHarness {
 static int checks;static final String ID="a".repeat(64);
 static void check(boolean value,String text){checks++;if(!value)throw new AssertionError(text);}
 static void await(CountDownLatch value,String text)throws Exception{check(value.await(5,TimeUnit.SECONDS),text);}
 interface Action {void run()throws Exception;}
 static void rejects(Action action,String text)throws Exception{try{action.run();throw new AssertionError(text);}catch(IllegalStateException expected){checks++;}}
 static byte[] response(String id){String json="{\"ok\":true,\"node_id\":\""+id+"\",\"proof\":\"router-vpn-private-agent-v1\"}";return ("HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n"+json).getBytes(StandardCharsets.UTF_8);}
 static final class ProofServer implements AutoCloseable {
  final ServerSocket server=new ServerSocket(0,8,InetAddress.getLoopbackAddress());final Thread thread;
  ProofServer()throws Exception{thread=new Thread(()->{while(!server.isClosed())try(Socket client=server.accept()){
   InputStream in=client.getInputStream();int match=0;byte[] end="\r\n\r\n".getBytes(StandardCharsets.US_ASCII);int b;
   while(match<4&&(b=in.read())>=0){match=b==end[match]?match+1:0;}client.getOutputStream().write(response(ID));
  }catch(Exception failure){if(!server.isClosed())throw new RuntimeException(failure);}},"loopback-entry-proof");thread.setDaemon(true);thread.start();}
  public void close()throws Exception{server.close();thread.join(1000);}
 }
 static final class Receiver implements AndroidViaEntryLatencyProbe.Callback {
  final CountDownLatch done=new CountDownLatch(1),cleanupFailed=new CountDownLatch(1);final AtomicInteger calls=new AtomicInteger();
  volatile AndroidViaEntryLatencyProbe.Result result;volatile Throwable error;
  public void progress(String text){if(text.contains("teardown is incomplete"))cleanupFailed.countDown();}
  public void finished(AndroidViaEntryLatencyProbe.Result result,Throwable error){this.result=result;this.error=error;calls.incrementAndGet();done.countDown();}
 }
 static final class Fixture implements AutoCloseable {
  final Context context=new Context();final Path folder;final ProofServer proof=new ProofServer();
  final List<FakeSocket> sockets=Collections.synchronizedList(new ArrayList<>());final List<String> resolved=Collections.synchronizedList(new ArrayList<>());
  final AtomicInteger proofs=new AtomicInteger(),aConnects=new AtomicInteger(),bConnects=new AtomicInteger();
  final CountDownLatch entered=new CountDownLatch(1),release=new CountDownLatch(1);
  volatile boolean blockResolve,blockSocket;volatile int wrongProof,failSample;volatile Runnable change;
  final AndroidRuntimeRegistry runtime;final AndroidViaEntryLatencyProbe probe;
  final AndroidNodeStore.Node entry,a,b;
  Fixture(Path root)throws Exception{
   check(!AndroidViaEntryLatencyProbe.hasActiveOperation(),"prior process owner drained");GoBackend.reset();AndroidVpnMutationGuard.busy=false;AndroidHomeStateStore.state=new AndroidHomeStateStore.Snapshot();NetworkCapabilities.uid=1000;android.os.Build.VERSION.SDK_INT=35;
   folder=Files.createTempDirectory(root,"probe-");
   SocketFactory factory=new SocketFactory(){public Socket createSocket(){FakeSocket socket=new FakeSocket(Fixture.this);sockets.add(socket);return socket;}
    public Socket createSocket(String h,int p){throw new AssertionError("uncaptured hostname socket");}public Socket createSocket(String h,int p,InetAddress l,int q){throw new AssertionError();}
    public Socket createSocket(InetAddress h,int p){throw new AssertionError();}public Socket createSocket(InetAddress h,int p,InetAddress l,int q){throw new AssertionError();}};
   context.network.idle=new Network(false,null,null);context.network.active=context.network.idle;
   context.network.vpn=new Network(true,host->{resolved.add(host);if(blockResolve&&host.equals("candidate-a.invalid")){entered.countDown();while(release.getCount()>0)try{release.await();}catch(InterruptedException ignored){}}
    byte last=host.equals("candidate-a.invalid")?(byte)10:host.equals("candidate-b.invalid")?(byte)20:(byte)1;
    return new InetAddress[]{InetAddress.getByAddress(new byte[]{127,0,0,last})};},factory);
   entry=node("entry");a=node("a");b=node("b");runtime=new AndroidRuntimeRegistry(context);probe=new AndroidViaEntryLatencyProbe(context,runtime,new AndroidTelemetry());
  }
  AndroidNodeStore.Node node(String id)throws Exception{
   JSONObject root=new JSONObject().put("node_id",ID).put("label",id);
   root.put("profile",new JSONObject().put("path_probe_url","http://127.0.0.1:"+proof.server.getLocalPort()+"/health"));
   root.put("profiles",new JSONObject().put("wg",new JSONObject().put("wg.conf",Base64.getEncoder().encodeToString("[Interface]\nPrivateKey=test\n".getBytes(StandardCharsets.UTF_8)))));
   Path file=folder.resolve(id+".json");Files.writeString(file,root.toString());return new AndroidNodeStore.Node(id,file.toFile());
  }
  Receiver start(){Receiver receiver=new Receiver();probe.measure(entry,Arrays.asList(a,b),3,receiver);return receiver;}
  void drained(){synchronized(sockets){check(sockets.stream().allMatch(value->value.closed),"every captured proof and candidate socket closed");}}
  public void close()throws Exception{
   release.countDown();synchronized(sockets){for(FakeSocket socket:sockets)socket.close();}
   if(GoBackend.releaseDown!=null)GoBackend.releaseDown.countDown();probe.cancel();
   long end=System.nanoTime()+3_000_000_000L;while(probe.isBusy()&&System.nanoTime()<end)Thread.sleep(10);
   if(runtime.wireGuard.getState()==Tunnel.State.UP){CountDownLatch down=new CountDownLatch(1);runtime.wireGuard.disconnectManaged((s,m,e)->down.countDown());down.await(3,TimeUnit.SECONDS);}
   runtime.wireGuard.close();proof.close();
  }
 }
 static final class FakeSocket extends Socket {
  final Fixture fixture;volatile boolean closed;int proof;
  FakeSocket(Fixture fixture){this.fixture=fixture;}
  public void connect(SocketAddress target,int timeout)throws IOException {
   InetAddress address=((InetSocketAddress)target).getAddress();int last=address.getAddress()[3]&255;
   if(last==1){proof=fixture.proofs.incrementAndGet();return;}
   int count=(last==10?fixture.aConnects:fixture.bConnects).incrementAndGet();
   if(fixture.blockSocket){fixture.entered.countDown();synchronized(this){while(!closed)try{wait();}catch(InterruptedException ignored){}}throw new SocketException("captured socket closed");}
   if(last==10&&count==fixture.failSample)throw new SocketException("sample timeout");
   try{Thread.sleep(last==10?6:25);}catch(InterruptedException interrupted){Thread.currentThread().interrupt();throw new SocketException("interrupted");}
   Runnable changed=fixture.change;if(changed!=null){fixture.change=null;changed.run();}
  }
  public void setSoTimeout(int timeout){}
  public OutputStream getOutputStream(){return new ByteArrayOutputStream();}
  public InputStream getInputStream(){return new ByteArrayInputStream(response(proof==fixture.wrongProof?"b".repeat(64):ID));}
  public synchronized void close(){closed=true;notifyAll();}
 }
 static void success(Path root)throws Exception{try(Fixture f=new Fixture(root)){
  GoBackend.enteredDown=new CountDownLatch(1);GoBackend.releaseDown=new CountDownLatch(1);Receiver r=f.start();await(GoBackend.enteredDown,"candidate worker reaches owned native stop");
  check(f.probe.isBusy()&&r.done.getCount()==1&&AndroidViaEntryLatencyProbe.hasActiveOperation(),"no candidate result released before native DOWN");
  check(f.proofs.get()==2&&f.resolved.containsAll(Arrays.asList("candidate-a.invalid","candidate-b.invalid","127.0.0.1")),"proofs and candidate DNS use captured VPN Network");f.drained();
  GoBackend.releaseDown.countDown();await(r.done,"successful candidate result delivered");check(r.error==null&&r.result!=null&&r.calls.get()==1,"one successful completion");
  r.result.requireCurrent();check(r.result.fastest()==f.a&&r.result.values.size()==2,"Fastest is the lowest fully valid routed candidate");
  check(r.result.measurement("a").samples==3&&r.result.measurement("a").medianMs>=1,"latency uses elapsed completed socket samples");
  check(f.runtime.wireGuard.getState()==Tunnel.State.DOWN&&!f.probe.isBusy(),"measurement retains no temporary VPN");
  Files.writeString(f.a.file.toPath(),"changed");rejects(r.result::requireCurrent,"source-changed result must be rejected");
 }}
 static void canceled(Path root,boolean dns)throws Exception{try(Fixture f=new Fixture(root)){
  f.blockResolve=dns;f.blockSocket=!dns;Receiver r=f.start();await(f.entered,dns?"resolver entered":"socket entered");f.probe.cancel();
  if(dns){check(f.probe.isBusy()&&r.done.getCount()==1&&GoBackend.downs.get()==0,"cancelled Future/interrupt is not resolver drain evidence");
   AndroidViaEntryLatencyProbe second=new AndroidViaEntryLatencyProbe(f.context,f.runtime,new AndroidTelemetry());Receiver rejected=new Receiver();second.measure(f.entry,List.of(f.a),3,rejected);await(rejected.done,"second activity rejected");check(rejected.error!=null&&GoBackend.ups.get()==1,"process reservation prevents a second temporary entry");f.release.countDown();}
  await(r.done,"cancel completes after actual worker drain");check(r.result==null&&r.error instanceof CancellationException&&r.calls.get()==1,"cancel never exposes prior partial results");
  check(GoBackend.downs.get()==1&&!f.probe.isBusy(),"cancel stops captured entry once after worker completion");f.drained();
 }}
 static void invalid(Path root,String kind)throws Exception{try(Fixture f=new Fixture(root)){
  if(kind.equals("proof-before"))f.wrongProof=1;
  else if(kind.equals("proof-after"))f.wrongProof=2;
  else if(kind.equals("foreign"))NetworkCapabilities.uid=2000;
  else if(kind.equals("unknown-owner"))NetworkCapabilities.uid=-1;
  else f.change=()->{try{switch(kind){case "source":Files.writeString(f.entry.file.toPath(),"changed");break;case "home":AndroidHomeStateStore.state=new AndroidHomeStateStore.Snapshot();AndroidHomeStateStore.state.sessionId="new owner";break;case "network":f.context.network.active=new Network(false,null,null);break;case "generation":f.runtime.wireGuard.onStateChange(Tunnel.State.DOWN);f.runtime.wireGuard.onStateChange(Tunnel.State.UP);break;default:throw new AssertionError(kind);}}catch(Exception e){throw new RuntimeException(e);}};
  Receiver r=f.start();await(r.done,"invalid "+kind+" completed");check(r.error!=null&&(r.result==null||r.result.values.isEmpty()),kind+" cannot expose a partially proved ranking");
  check(GoBackend.downs.get()==1&&f.runtime.wireGuard.getState()==Tunnel.State.DOWN,"invalid "+kind+" closes only its temporary entry");f.drained();
 }}
 static void partial(Path root)throws Exception{try(Fixture f=new Fixture(root)){
  f.failSample=2;Receiver r=f.start();await(r.done,"partial candidate completes");check(r.error==null&&r.result.measurement("a").failed==1,"failed candidate sample remains a failure, not zero time");
  check(r.result.fastest()==f.b,"partial candidate cannot win measured Fastest");
 }}
 static void api29(Path root)throws Exception{try(Fixture f=new Fixture(root)){
  android.os.Build.VERSION.SDK_INT=29;Receiver r=f.start();await(r.done,"API29 native capture measurement completes");
  check(r.error==null&&r.result!=null&&f.proofs.get()==2,"API29 proves the captured native VPN path without calling an absent API30 method");r.result.requireCurrent();
 }}
 static void cleanupRetry(Path root)throws Exception{try(Fixture f=new Fixture(root)){
  GoBackend.failDown.set(1);Receiver r=f.start();await(r.cleanupFailed,"unconfirmed DOWN retained");
  check(f.probe.isBusy()&&r.done.getCount()==1&&AndroidViaEntryLatencyProbe.hasActiveOperation(),"failed teardown keeps reservation and all results private");
  AndroidViaEntryLatencyProbe recreated=new AndroidViaEntryLatencyProbe(f.context,f.runtime,new AndroidTelemetry());
  check(!recreated.isBusy()&&AndroidViaEntryLatencyProbe.cancelActiveOperation(),"recreated Activity can cancel/retry the retained process operation");
  await(r.done,"owned cleanup retry finishes");check(GoBackend.downs.get()==2&&r.result==null&&r.error instanceof CancellationException,"Cancel retries the exact retained teardown without publishing values");f.drained();
 }}
 static void replacedDuringStop(Path root)throws Exception{try(Fixture f=new Fixture(root)){
  CountDownLatch replacement=new CountDownLatch(1);GoBackend.beforeDown=()->f.runtime.wireGuard.connectManaged(f.entry.file,(s,m,e)->replacement.countDown());
  Receiver r=f.start();await(r.done,"old measurement retires");await(replacement,"replacement connects");
  check(r.result==null&&r.error instanceof NativeWireGuardController.SessionReplaced,"completion cannot capture a replacement generation as measured provenance");
  check(f.runtime.wireGuard.getState()==Tunnel.State.UP&&GoBackend.ups.get()==2&&GoBackend.downs.get()==1,"old stop completion leaves replacement active");
  f.probe.cancel();check(f.runtime.wireGuard.getState()==Tunnel.State.UP&&GoBackend.downs.get()==1,"late Cancel never tears down replacement");
 }}
 static void capturedController(Path root)throws Exception{try(Fixture f=new Fixture(root)){
  CountDownLatch up=new CountDownLatch(1);AtomicReference<NativeWireGuardController.CapturedSession> captured=new AtomicReference<>();
  f.runtime.wireGuard.connectManagedCaptured(f.entry.file,(session,state,message,error)->{captured.set(session);up.countDown();});await(up,"captured entry started");check(captured.get().current(),"actual controller capture owns current proved path");
  CountDownLatch next=new CountDownLatch(1);f.runtime.wireGuard.connectManaged(f.entry.file,(s,m,e)->next.countDown());await(next,"different managed owner started");check(!captured.get().current(),"new managed generation revokes old capture");
  CountDownLatch closed=new CountDownLatch(1);AtomicReference<Throwable> failure=new AtomicReference<>();captured.get().disconnect((s,m,e)->{failure.set(e);closed.countDown();});await(closed,"old captured stop rejected");
  check(failure.get() instanceof NativeWireGuardController.SessionReplaced&&GoBackend.downs.get()==0&&f.runtime.wireGuard.getState()==Tunnel.State.UP,"captured stop must never call backend DOWN for replacement");
 }}
 static void staleResult(Path root,String kind)throws Exception{try(Fixture f=new Fixture(root)){
  Receiver r=f.start();await(r.done,"fresh result before "+kind);check(r.error==null,"fresh measurement succeeded");
  switch(kind){case "cancel":f.probe.cancel();break;case "home":AndroidHomeStateStore.state.sessionId="changed";break;case "network":f.context.network.active=new Network(false,null,null);break;case "new-measurement":f.probe.unmeasured(f.entry,List.of(f.b));break;case "generation":CountDownLatch done=new CountDownLatch(1);f.runtime.wireGuard.disconnectManaged((s,m,e)->done.countDown());await(done,"new operation generation");break;default:throw new AssertionError();}
  rejects(r.result::requireCurrent,kind+" invalidates the measured decision");
 }}
 public static void main(String[] args)throws Exception{
  Path root=Path.of(args[0]);if(args.length>1&&args[1].equals("captured")){capturedController(root);return;}
  if(args.length>1&&args[1].equals("route")){success(root);return;}
  success(root);canceled(root,true);canceled(root,false);for(String invalid:List.of("proof-before","proof-after","foreign","unknown-owner","source","home","network","generation"))invalid(root,invalid);
  partial(root);api29(root);cleanupRetry(root);replacedDuringStop(root);capturedController(root);for(String stale:List.of("cancel","home","network","new-measurement","generation"))staleResult(root,stale);
  check(!AndroidViaEntryLatencyProbe.hasActiveOperation(),"all process owners settled");System.out.println("Android shipping via-entry measurement: PASS "+checks+" checks (Network/backend boundary doubles; real loopback startup proof)");
 }
}
''',
}


def main():
    with tempfile.TemporaryDirectory(prefix="routervpn-via-entry-") as work:
        base = Path(work)
        for name, text in SOURCES.items():
            target = base / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(text)
        for name in CLASSES:
            shutil.copyfile(JAVA / (name + ".java"), base / "com/eabusham/routervpn" / (name + ".java"))

        def run(argument=None):
            built = subprocess.run(["javac", "--release", "17", "-cp", "/usr/share/java/com.android.json.jar", "-d", str(base), *map(str, base.rglob("*.java"))], text=True, capture_output=True, timeout=30)
            assert built.returncode == 0, built.stderr
            return subprocess.run(["java", "-cp", str(base) + ":/usr/share/java/com.android.json.jar", "com.eabusham.routervpn.ViaEntryHarness", str(base), *([] if argument is None else [argument])], text=True, capture_output=True, timeout=60)

        result = run()
        assert result.returncode == 0, result.stdout + result.stderr
        print(result.stdout.strip())
        # Removing the exact owner check recreates the replacement-disconnect bug.
        native = base / "com/eabusham/routervpn/NativeWireGuardController.java"
        original = native.read_text()
        changed = original.replace('if (sessionGeneration.get()!=owner) { callback.done(state,"Captured entry was replaced.",new SessionReplaced()); return; }', 'if (false) { callback.done(state,"Captured entry was replaced.",new SessionReplaced()); return; }')
        assert changed != original
        native.write_text(changed)
        result = run("captured")
        assert result.returncode != 0 and "captured stop must never" in result.stderr, result.stdout + result.stderr
        native.write_text(original)
        # A resolver bypass cannot stand in for the captured VPN's DNS path.
        # Use a fixed loopback answer so this negative never queries public DNS.
        probe = base / "com/eabusham/routervpn/AndroidViaEntryLatencyProbe.java"
        original = probe.read_text()
        changed = original.replace("network::getAllByName", "host -> new java.net.InetAddress[]{java.net.InetAddress.getLoopbackAddress()}")
        assert changed != original
        probe.write_text(changed)
        result = run("route")
        assert result.returncode != 0 and "proofs and candidate DNS use captured" in result.stderr, result.stdout + result.stderr
        print("Android via-entry ownership and captured-resolver negative controls: rejected")


if __name__ == "__main__":
    main()
