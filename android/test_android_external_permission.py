#!/usr/bin/env python3
"""Execute the shipping unified external permission and restored-state bridge."""
from pathlib import Path
import importlib.util
import os
import re
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
JAVA = ROOT / "android/app/src/main/java/com/eabusham/routervpn"
spec = importlib.util.spec_from_file_location("external_permission_widgets", ROOT / "android/test_android_tor_form.py")
T = importlib.util.module_from_spec(spec)
spec.loader.exec_module(T)

BOUNDARIES = r'''package com.eabusham.routervpn;
import android.content.Context;import java.io.*;import java.util.*;import java.nio.file.*;import java.nio.charset.*;import org.json.*;
final class AndroidPrivateFileStore {static byte[] read(File f,int max)throws Exception{byte[] b=Files.readAllBytes(f.toPath());if(b.length==0||b.length>max)throw new IllegalArgumentException("bounded private input required");return b;}}
final class AndroidTorProfile {static boolean isTor(String p){return "tor".equals(p)||"tor-bridge".equals(p);}static String strictText(byte[] b)throws Exception{return StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT).decode(java.nio.ByteBuffer.wrap(b)).toString();}static String digest(byte[] b)throws Exception{return java.util.HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256").digest(b));}}
final class AndroidVpnMutationGuard {static boolean busy;static boolean isBusy(Context c){return busy;}}
final class AndroidHomeStateStore {static final class Snapshot{boolean connected;long pathGeneration;String sessionId="",phase="off",pathProof="not-run",logicalMode="",runtimeMode="",fallback="",activeNodeId="",activeEntryId="",activeExitId="",activeEntryMode="",activeExternalId="",activeExternalProtocol="";}static Snapshot current=new Snapshot();static Snapshot snapshot(Context c){return current;}static long advancePathGeneration(Context c){return ++current.pathGeneration;}}
final class AndroidNodeStore {
 static final int MAX_BUNDLE=32*1024*1024;static final List<Node> nodes=new ArrayList<>();
 static final class Node {final String id,name,endpoint="";final File file;Node(String id,File f){this.id=id;name=id;file=f;}}
 AndroidNodeStore(Context c){}List<Node> list(){return new ArrayList<>(nodes);}String activeId(){return nodes.isEmpty()?"":nodes.get(0).id;}File file(String id){for(Node n:nodes)if(n.id.equals(id))return n.file;return null;}
 static void validateBundle(JSONObject b)throws Exception{b.getJSONObject("profiles");b.getJSONArray("modes");}
}
final class AndroidStandardExitStore {
 static final Map<String,Entry> saved=new HashMap<>();
 static final class Entry {String id="saved-exit",protocol="openvpn",secret="private-endpoint-key",policy="captured-home",expectedPublicIp="8.8.4.4";String startupMode="smart-auto",responseMap="";boolean autoConnect;}
 AndroidStandardExitStore(Context c){}List<Entry> list()throws Exception{List<Entry> list=new ArrayList<>();for(Entry e:saved.values())list.add(copy(e));return list;}Entry get(String id)throws Exception{Entry e=saved.get(id);if(e==null)throw new IllegalArgumentException("missing exit");return copy(e);}
 static void validateExecution(Entry e,boolean entry,String execution){if(!List.of("local","server","auto").contains(execution)||!execution.equals("local")&&(!entry||!(e.protocol.equals("shadowsocks")||e.protocol.equals("openvpn")&&!e.responseMap.isEmpty())))throw new IllegalArgumentException("unowned execution");}
 static void validate(Entry e){if(e==null||e.id.isEmpty())throw new IllegalArgumentException("missing saved exit");}
 static Entry copy(Entry e){Entry x=new Entry();x.id=e.id;x.protocol=e.protocol;x.secret=e.secret;x.policy=e.policy;x.expectedPublicIp=e.expectedPublicIp;x.startupMode=e.startupMode;x.autoConnect=e.autoConnect;x.responseMap=e.responseMap;return x;}
 static String snapshot(Entry e)throws Exception{return new JSONObject().put("startup_mode",e.startupMode).put("auto_connect",e.autoConnect).put("id",e.id).put("protocol",e.protocol).put("secret",e.secret).put("policy",e.policy).put("expected",e.expectedPublicIp).put("openvpn_response_probes",e.responseMap).toString();}
}
final class NativeWireGuardController {}final class NativeAmneziaWGController {}final class NativeXrayController {}
final class NativeSingBoxController {
 static final class ModeInfo {final String id,name;ModeInfo(String id,String name){this.id=id;this.name=name;}}
 // PRODUCTION_TRANSPORT_PREDICATES
}
final class AndroidNativeCompositeProfile {
 // PRODUCTION_COMPOSITE_PREDICATE
}
final class AndroidModeOrchestrator {
 interface Callback{void progress(String message);void finished(boolean ok,String mode,String message);default void owned(String id){}default void proved(String session,String raw,String source){}}
 void startup(File file,String mode,String raw,String source,Callback cb){throw new AssertionError("external permission cannot dispatch Router startup");}
 String captureSource(File f,String session,String raw)throws Exception{return Files.readString(f.toPath());}void restoreCaptured(File f,String raw,String logical,String fallback,String source,Callback cb){}void disconnectCaptured(String session,Callback cb){cb.finished(true,"","stopped");}
 void disconnect(Callback cb){cb.finished(true,"","stopped");}void auto(File f,boolean smart,Callback cb){}void all(File f,Callback cb){}void custom(File f,List<String> l,Callback cb){}void logical(File f,String m,Callback cb){}
}
final class AndroidMultihopRuntime {
 interface Callback{void progress(String s);void finished(boolean ok,String s);default void owned(String id){}}
 String activeExecution(){return "local";}String activeSelectedExecution(){return "local";}void restoreCaptured(AndroidNodeStore.Node a,AndroidNodeStore.Node b,String mode,String policy,String selected,String entry,Callback cb){}boolean disconnectAndDrainCaptured(String session){return true;}
 boolean isConnected(){return false;}boolean isActiveOrTransitioning(){return false;}String activeEntryId(){return "";}String activeExitId(){return "";}String activeEntryMode(){return "";}String activeExitMode(){return "";}
 void disconnect(){}void connect(AndroidNodeStore.Node a,AndroidNodeStore.Node b,String mode,String execution,String entry,Callback cb){}List<NativeSingBoxController.ModeInfo> listSupportedExitModes(File f){return Collections.emptyList();}
}
final class AndroidStandardExitRuntime {
 interface Callback{void progress(String s);void finished(boolean ok,String s);default void owned(String id){}}
 int starts;String mode,execution="local",selected="local";File entry;AndroidStandardExitStore.Entry exit;
 String capturedRequestedExecution(AndroidHomeStateStore.Snapshot s){return execution;}String capturedExternalExecution(AndroidHomeStateStore.Snapshot s){return selected;}
 void restoreCaptured(File f,AndroidStandardExitStore.Entry e,String mode,String execution,String winner,Callback cb){connect(f,e,mode,execution,cb);selected=winner;}
 void connect(File f,AndroidStandardExitStore.Entry e,String m,String execution,Callback cb){this.execution=execution;selected=execution.equals("auto")?"server":execution;connect(f,e,m,cb);}
 String capturedTorExit(AndroidHomeStateStore.Snapshot s){return "8.8.4.4";}String capturedExternalExit(AndroidHomeStateStore.Snapshot s){return "8.8.4.4";}boolean disconnectAndDrainCaptured(String id){return true;}
 boolean isActiveOrTransitioning(){return false;}void disconnect(){}boolean disconnectCaptured(String id){return true;}
 void connectDirect(AndroidStandardExitStore.Entry e,Callback cb){starts++;mode="external";exit=e;cb.finished(true,"owned direct");}
 void connect(File f,AndroidStandardExitStore.Entry e,Callback cb){connect(f,e,"wg",cb);}
 void connect(File f,AndroidStandardExitStore.Entry e,String m,Callback cb){starts++;entry=f;mode=m;exit=e;cb.finished(true,"owned entry");}
}
final class AndroidRuntimeRegistry {
 static AndroidRuntimeRegistry instance=new AndroidRuntimeRegistry();static AndroidRuntimeRegistry get(Context c){return instance;}
 final NativeWireGuardController wireGuard=new NativeWireGuardController();final NativeAmneziaWGController amneziaWG=new NativeAmneziaWGController();final NativeSingBoxController singBox=new NativeSingBoxController();final NativeXrayController xray=new NativeXrayController();final AndroidModeOrchestrator orchestrator=new AndroidModeOrchestrator();final AndroidMultihopRuntime multihop=new AndroidMultihopRuntime();final AndroidStandardExitRuntime standardExit=new AndroidStandardExitRuntime();
}
// Startup has its own shipping-policy/permission fixture. This suite never
// creates a startup capture or records a single-Router proof.
final class AndroidStartupPolicy {
 static final class Attempt {String nonce="",mode="",source="",lastRaw="",entryMode="wg",exitMode="",execution="local";AndroidNodeStore.Node node,entry,exit;AndroidStandardExitStore.Entry external;boolean external(){return external!=null;}boolean multihop(){return entry!=null;}void requireCurrent(Context c,AndroidNodeStore n,AndroidUnifiedConnectionController o){throw new AssertionError("unexpected startup capture");}void dispatched(){}void cancel(){}}
 static Attempt restore(String nonce){return null;}static void cancelPending(){}static boolean recordProven(Context c,AndroidNodeStore n,File f,String session,String raw,String source){return false;}
}
'''

HARNESS = r'''package com.eabusham.routervpn;
import android.app.*;import android.os.*;import java.nio.file.*;import java.nio.charset.*;import java.util.*;import org.json.*;
public class ExternalPermissionTest {
 // ALL_CAPTURED_MODES
 static int checks;static void check(boolean ok,String message){checks++;if(!ok)throw new AssertionError(message);}
 static final class Callback implements AndroidUnifiedConnectionController.Callback {int completions;boolean ok;public void progress(String s){}public void finished(boolean b,String s){completions++;ok=b;}}
 static final class Fixture {
  final Activity activity=new Activity();final AndroidNodeStore nodes=new AndroidNodeStore(activity);final AndroidStandardExitStore.Entry exit=new AndroidStandardExitStore.Entry();final AndroidNodeStore.Node entry;
  AndroidUnifiedConnectionController controller;final Callback callback=new Callback();final Path file;
  Fixture(Path root)throws Exception{AndroidNodeStore.nodes.clear();AndroidStandardExitStore.saved.clear();AndroidRuntimeRegistry.instance=new AndroidRuntimeRegistry();AndroidVpnMutationGuard.busy=false;AndroidHomeStateStore.current=new AndroidHomeStateStore.Snapshot();android.net.VpnService.needsPermission=true;
   file=Files.createTempFile(root,"entry-",".json");JSONObject profiles=new JSONObject();JSONArray modes=new JSONArray();for(String mode:ALL){profiles.put(mode,new JSONObject());modes.put(new JSONObject().put("id",mode).put("name","Captured "+mode));}
   modes.put(new JSONObject().put("id","wg").put("name","duplicate"));modes.put(new JSONObject().put("id","unowned"));Files.writeString(file,new JSONObject().put("profiles",profiles).put("modes",modes).toString());entry=new AndroidNodeStore.Node("entry-owned",file.toFile());AndroidNodeStore.nodes.add(entry);controller=new AndroidUnifiedConnectionController(activity,nodes);save();}
  void save(){AndroidStandardExitStore.saved.put(exit.id,AndroidStandardExitStore.copy(exit));}
  AndroidStandardExitRuntime runtime(){return AndroidRuntimeRegistry.instance.standardExit;}
  Bundle request(String mode,boolean direct){controller.connectExternal(entry,exit,direct,mode,callback);Bundle state=new Bundle();controller.savePending(state);return state;}
  void restore(Bundle state){controller.close();controller=new AndroidUnifiedConnectionController(activity,nodes);controller.restorePending(state,callback);}
  void allow(){check(controller.onActivityResult(AndroidUnifiedConnectionController.PREPARE_UNIFIED,Activity.RESULT_OK),"permission result ignored");}
 }
 static void allModes(Path root)throws Exception{
  for(String protocol:new String[]{"wireguard","amneziawg","socks5","http","https","shadowsocks","hysteria2","openvpn","tor","tor-bridge"})for(String mode:ALL)for(boolean restore:new boolean[]{false,true}){
   Fixture f=new Fixture(root);f.exit.protocol=protocol;f.save();Bundle state=f.request(mode,false);
   check(f.activity.permissionRequest==AndroidUnifiedConnectionController.PREPARE_UNIFIED&&f.runtime().starts==0,"external test ran before Android permission");
   check(!state.values.toString().contains(f.exit.secret)&&!state.values.toString().contains(f.exit.policy),"private profile was copied into Android saved state");
   if(restore)f.restore(state);f.allow();check(f.callback.ok&&f.callback.completions==1&&f.runtime().starts==1,"captured permission request was not completed");
   check(mode.equals(f.runtime().mode)&&f.runtime().entry.equals(f.entry.file)&&protocol.equals(f.runtime().exit.protocol),"temporary external/Tor path discarded its selected native entry");
  }
 }
 static void directAndFrozen(Path root)throws Exception{
  for(boolean restore:new boolean[]{false,true}){Fixture f=new Fixture(root);Bundle state=f.request("reality-xhttp",true);if(restore)f.restore(state);f.allow();check(f.callback.ok&&f.runtime().mode.equals("external")&&f.runtime().entry==null,"direct external capture acquired an entry");}
  Fixture f=new Fixture(root);f.request("max-quic-awg",false);String secret=f.exit.secret;f.exit.secret="new-caller-value";f.exit.protocol="http";f.allow();check(f.callback.ok&&f.runtime().exit.secret.equals(secret)&&f.runtime().exit.protocol.equals("openvpn"),"permission reused mutable caller credentials");
  Fixture modes=new Fixture(root);List<NativeSingBoxController.ModeInfo> values=modes.controller.supportedNativeEntryModes(modes.entry);check(values.size()==19,"native entry picker omitted or duplicated modes");for(int i=0;i<ALL.length;i++)check(values.get(i).id.equals(ALL[i])&&values.get(i).name.endsWith("["+ALL[i]+"]"),"native entry identity and displayed label diverged");
 }
 static void execution(Path root)throws Exception{
  for(String protocol:List.of("shadowsocks","openvpn"))for(String choice:List.of("local","server","auto"))for(boolean restore:new boolean[]{false,true}){
   Fixture f=new Fixture(root);f.exit.protocol=protocol;f.exit.responseMap=protocol.equals("openvpn")?"captured-private-two-host-map":"";f.save();f.controller.connectExternal(f.entry,f.exit,false,"max-quic-awg",choice,f.callback);Bundle state=new Bundle();f.controller.savePending(state);
   check(f.runtime().starts==0,"execution launched before permission");if(restore)f.restore(state);f.allow();check(f.callback.ok&&f.runtime().execution.equals(choice)&&f.runtime().exit.responseMap.equals(f.exit.responseMap),"permission lost external execution choice or captured remote map");
  }
  Fixture tampered=new Fixture(root);tampered.exit.protocol="shadowsocks";tampered.save();tampered.controller.connectExternal(tampered.entry,tampered.exit,false,"wg","auto",tampered.callback);Bundle state=new Bundle();tampered.controller.savePending(state);state.putString("multihop_execution_pending","server");tampered.restore(state);tampered.allow();check(!tampered.callback.ok&&tampered.runtime().starts==0,"restored permission substituted Server for Compare");
  Fixture direct=new Fixture(root);direct.exit.protocol="shadowsocks";direct.save();direct.controller.connectExternal(null,direct.exit,true,"wg","server",direct.callback);check(!direct.callback.ok&&direct.runtime().starts==0,"direct path acquired a server execution owner");
 }
 static void changes(Path root)throws Exception{
  for(String change:new String[]{"entry-file","exit-policy","exit-key","exit-removed","entry-removed","mode","direct","digest","legacy","permission-denied","busy","closed"})for(boolean restore:new boolean[]{false,true}){
   Fixture f=new Fixture(root);Bundle state=f.request("max-quic-awg",false);
   if(change.equals("entry-file"))Files.writeString(f.file,"{}");if(change.equals("entry-removed"))Files.delete(f.file);
   if(change.equals("exit-policy")){f.exit.policy="changed-dns";f.save();}if(change.equals("exit-key")){f.exit.secret="changed-key";f.save();}if(change.equals("exit-removed"))AndroidStandardExitStore.saved.clear();
   if(change.equals("mode"))state.putString("multihop_entry_mode_pending","wg");if(change.equals("direct"))state.putBoolean("routervpn.pending.external_direct",true);if(change.equals("digest"))state.putString("external_profile_digest_pending","0".repeat(64));if(change.equals("legacy"))state.values.remove("external_request_digest_pending");
   boolean stateOnly=Set.of("mode","direct","digest","legacy").contains(change);if(restore||stateOnly)f.restore(state);
   if(change.equals("permission-denied")){f.controller.onActivityResult(AndroidUnifiedConnectionController.PREPARE_UNIFIED,0);}else{if(change.equals("busy"))AndroidVpnMutationGuard.busy=true;if(change.equals("closed"))f.controller.close();f.allow();}
   check(f.runtime().starts==0&&!f.callback.ok,"changed external permission selection started a different graph: "+change+"/"+restore);
  }
  Fixture pending=new Fixture(root);pending.request("wg",false);Callback rejected=new Callback();pending.controller.connectExternal(pending.entry,pending.exit,false,"max",rejected);check(rejected.completions==1&&!rejected.ok,"new request overwrote pending external permission");pending.allow();check(pending.callback.ok&&pending.runtime().mode.equals("wg"),"second request replaced the original permission owner");
 }
 public static void main(String[]args)throws Exception{Path root=Path.of(args[0]);allModes(root);directAndFrozen(root);execution(root);changes(root);System.out.println("Android external permission: "+checks+" checks; all19 entries, ten exit protocols, restored/cancelled/stale requests");}
}
'''


def main():
    jar = Path(os.environ.get("ANDROID_JSON_JAR", "/usr/share/java/com.android.json.jar"))
    if not jar.is_file() or not shutil.which("javac"):
        raise RuntimeError("JDK and Android JSON are required for unified permission tests")
    ui = dict(T.UI)
    ui["android/content/SharedPreferences.java"] = "package android.content; public interface SharedPreferences {String getString(String key,String fallback);}"
    ui["android/os/Bundle.java"] = ui["android/os/Bundle.java"][:-1] + "public void putStringArrayList(String k,java.util.ArrayList<String> v){values.put(k,v);}public java.util.ArrayList<String> getStringArrayList(String k){return (java.util.ArrayList<String>)values.get(k);}public boolean containsKey(String k){return values.containsKey(k);}}"
    native = (JAVA / "NativeSingBoxController.java").read_text()
    methods = []
    for name in ("nativeMultihopEntry", "nativeWireGuardFamily", "nativeNaiveFamily", "nativePQFamily"):
        matches = re.findall(r"(?ms)^    static boolean " + name + r"\(String mode\) \{\n.*?^    \}", native)
        assert len(matches) == 1, "exact shipping native mode predicate is required"
        methods.append(matches[0])
    composite = re.findall(r"(?ms)^    static boolean isMode\(String mode\) \{\n.*?^    \}", (JAVA / "AndroidNativeCompositeProfile.java").read_text())
    assert len(composite) == 1
    boundaries = BOUNDARIES.replace(" // PRODUCTION_TRANSPORT_PREDICATES", "\n".join(methods)).replace(" // PRODUCTION_COMPOSITE_PREDICATE", composite[0])
    modes = next(line for line in T.T.HARNESS.splitlines() if "static final String[] ALL=" in line)
    with tempfile.TemporaryDirectory(prefix="routervpn-external-permission-") as directory:
        temp = Path(directory)
        for name, source in ui.items():
            path = temp / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(source)
        app = temp / "com/eabusham/routervpn"
        app.mkdir(parents=True)
        (app / "Boundaries.java").write_text(boundaries)
        (app / "ExternalPermissionTest.java").write_text(HARNESS.replace(" // ALL_CAPTURED_MODES", modes))
        target = app / "AndroidUnifiedConnectionController.java"
        source = (JAVA / target.name).read_text()
        target.write_text(source)
        compile_args = ["javac", "--release", "17", "-encoding", "UTF-8", "-proc:none", "-cp", str(jar), "-d", str(temp / "classes"), *map(str, temp.rglob("*.java"))]
        subprocess.run(compile_args, check=True, timeout=45)
        data = temp / "data"
        data.mkdir()
        subprocess.run(["java", "-cp", os.pathsep.join((str(temp / "classes"), str(jar))), "com.eabusham.routervpn.ExternalPermissionTest", str(data)], check=True, timeout=20)


if __name__ == "__main__":
    main()
