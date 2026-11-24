#!/usr/bin/env python3
"""Exercise real ordered stores and history monitors without Android VPN doubles.

NodeStore, imported store, Home, private-file I/O, history stores and the new
history readback run unchanged. Android syscalls use the existing real Unix
file adapter. Runtime admission is an explicit idle boundary; the separate
full-service fixture tests native/lifecycle authority. No device claim follows.
"""
from pathlib import Path
import ast
import hashlib
import json
import os
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
JAVA = ROOT / "android/app/src/main/java/com/eabusham/routervpn"
APP = "com/eabusham/routervpn/"
ACTUAL = ("AndroidNodeStore", "AndroidStandardExitStore", "AndroidHomeStateStore",
          "AndroidPrivateFileStore", "AndroidProfileSelection", "AndroidNumericAddress",
          "AndroidExternalProtection", "AndroidConnectionSelection", "AndroidOrderedLatencyStore",
          "AndroidOrderedExecutionLatencyCapture", "AndroidOrderedExecutionLatencyStore",
          "AndroidOrderedLatencySourceTransaction")
FAMILIES = ("monitors", "scope", "sources", "epochs", "ordinary", "execution", "rollback")


def literal(path, name):
    tree = ast.parse(path.read_text())
    values = [ast.literal_eval(item.value) for item in tree.body if isinstance(item, ast.Assign)
              and any(isinstance(target, ast.Name) and target.id == name for target in item.targets)]
    assert len(values) == 1, name
    return values[0]


def block(source, signature):
    assert source.count(signature) == 1, signature
    start = source.index(signature)
    at = source.index("{", start)
    depth, end = 1, at + 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[start:end]


CONTEXT = r'''package android.content;
public final class Context {
 public static final int MODE_PRIVATE=0;private final java.io.File files;
 private final java.util.Map<String,MemoryPreferences> values=new java.util.HashMap<>();
 public Context(java.io.File files){this.files=files;}public Context getApplicationContext(){return this;}
 public java.io.File getFilesDir(){return files;}
 public synchronized MemoryPreferences getSharedPreferences(String name,int mode){return values.computeIfAbsent(name,k->new MemoryPreferences());}
}
'''
PREFS = r'''package android.content;
public interface SharedPreferences {
 String getString(String k,String d);boolean getBoolean(String k,boolean d);long getLong(String k,long d);java.util.Map<String,?> getAll();Editor edit();
 interface Editor{Editor putString(String k,String v);Editor putBoolean(String k,boolean v);Editor putLong(String k,long v);Editor remove(String k);void apply();boolean commit();}
}
'''
MEMORY = r'''package android.content;
public final class MemoryPreferences implements SharedPreferences {
 private final Object internal=new Object();private final java.util.Map<String,Object> values=new java.util.HashMap<>();
 public String getString(String k,String d){synchronized(internal){return (String)values.getOrDefault(k,d);}}
 public boolean getBoolean(String k,boolean d){synchronized(internal){return (Boolean)values.getOrDefault(k,d);}}
 public long getLong(String k,long d){synchronized(internal){return (Long)values.getOrDefault(k,d);}}
 public java.util.Map<String,?> getAll(){synchronized(internal){return new java.util.HashMap<>(values);}}
 public Editor edit(){return new Editor(){final java.util.Map<String,Object> next=new java.util.HashMap<>();
 public Editor putString(String k,String v){next.put(k,v);return this;}public Editor putBoolean(String k,boolean v){next.put(k,v);return this;}public Editor putLong(String k,long v){next.put(k,v);return this;}public Editor remove(String k){next.put(k,null);return this;}
 public void apply(){commit();}public boolean commit(){synchronized(internal){for(var e:next.entrySet())if(e.getValue()==null)values.remove(e.getKey());else values.put(e.getKey(),e.getValue());return true;}}};}
}
'''
BOUNDARY = r'''package com.eabusham.routervpn;
import org.json.*;import java.util.*;import java.nio.charset.StandardCharsets;import android.content.Context;
// The source/monitor fixture supplies stable idle admission only. It cannot
// create a native service, paired proof, permission result or live history owner.
final class AndroidVpnMutationGuard {static boolean isBusy(Context c){return false;}}
final class AndroidRuntimeRegistry {
 static final class Engine{boolean isRunning(){return false;}boolean isActiveOrTransitioning(){return false;}String getState(){return "DOWN";}}
 static final class WG{com.wireguard.android.backend.Tunnel.State getState(){return com.wireguard.android.backend.Tunnel.State.DOWN;}}
 static final class AWG{org.amnezia.awg.backend.Tunnel.State getState(){return org.amnezia.awg.backend.Tunnel.State.DOWN;}}
 final Engine orchestrator=new Engine(),multihop=new Engine(),singBox=new Engine(),xray=new Engine();final WG wireGuard=new WG();final AWG amneziaWG=new AWG();
 static AndroidRuntimeRegistry get(Context c){return new AndroidRuntimeRegistry();}
}
final class NativeSingBoxController{static boolean nativeMultihopEntry(String mode){return java.util.List.of("wg","awg2-fast","awg2-strong").contains(mode);}}
final class AndroidImportedRouterPath{static boolean supports(String first,String last){return false;}}
final class AndroidExternalAmnezia{static JSONObject endpoint(AndroidStandardExitStore.Entry e){throw new AssertionError("AWG transport outside store fixture");}}
final class AndroidOpenVPN {
 static JSONObject endpoint(AndroidStandardExitStore.Entry e,String tag){throw new AssertionError("OpenVPN transport outside store fixture");}
 static void validatePairing(AndroidStandardExitStore.Entry e){if(e.openVPNPairing!=null)throw new AssertionError("OpenVPN pairing outside store fixture");}
 static void validateResponseProbes(AndroidStandardExitStore.Entry e){if(e.openVPNResponseProbes!=null||e.openVPNStartLayers!=null)throw new AssertionError("OpenVPN probes outside store fixture");}
}
final class AndroidTorProfile {
 static boolean isTor(String p){return "tor".equals(p)||"tor-bridge".equals(p);}
 static void validate(AndroidStandardExitStore.Entry e){throw new AssertionError("Tor capture outside store fixture");}
 static String strictText(byte[] raw)throws Exception{return java.nio.charset.StandardCharsets.UTF_8.newDecoder().onMalformedInput(java.nio.charset.CodingErrorAction.REPORT).onUnmappableCharacter(java.nio.charset.CodingErrorAction.REPORT).decode(java.nio.ByteBuffer.wrap(raw)).toString();}
}
final class AndroidExternalPolicy {
 // CAPTURE_TYPE_SOURCE
 // Native imported construction remains outside this history-only fixture.
 static Captured captureImportedEntry(AndroidStandardExitStore.Entry e){throw new AssertionError("Native imported compilation outside immutable readback fixture");}
 // PURE_POLICY_SOURCE
 static JSONObject profile(AndroidStandardExitStore.Entry e){throw new AssertionError("Native imported compilation outside immutable readback fixture");}
}
'''

HARNESS = r'''package com.eabusham.routervpn;
import android.content.Context;import java.io.*;import java.nio.file.*;import java.nio.charset.StandardCharsets;
import java.util.*;import java.util.concurrent.*;import java.util.concurrent.atomic.*;import java.lang.management.*;import org.json.*;
public final class OrderedHistorySourceTest {
 static int checks;
 interface Action{void run()throws Exception;}
 static void check(boolean ok,String why){if(!ok)throw new AssertionError(why);checks++;}
 static void reject(Action action,String why)throws Exception{try{action.run();}catch(Exception expected){checks++;return;}throw new AssertionError(why);}
 static Object field(Class<?> type,String name)throws Exception{var f=type.getDeclaredField(name);f.setAccessible(true);return f.get(null);}
 static byte[] bytes(String value){return value.getBytes(StandardCharsets.UTF_8);}
 static JSONObject bundle(int position,JSONArray refs)throws Exception{
  var keys=java.security.KeyPairGenerator.getInstance("X25519");var pair=keys.generateKeyPair();byte[] u=((java.security.interfaces.XECPublicKey)pair.getPublic()).getU().toByteArray(),key=new byte[32];for(int i=0;i<Math.min(u.length,32);i++)key[i]=u[u.length-1-i];
  String peer=Base64.getEncoder().encodeToString(key),proof=HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256").digest(bytes("router-vpn-node-proof-v1\n"+peer)));
  JSONObject profile=new JSONObject().put("id","node-"+position).put("node_proof_id",proof).put("api_token","original-private-"+position).put("name","Original "+position);
  JSONObject assets=new JSONObject().put("wg",new JSONObject().put("wg.conf",Base64.getEncoder().encodeToString(bytes("[Peer]\nPublicKey="+peer+"\n"))));
  if(position==2){profile.put("multihop_enabled",true).put("multihop_execution","local").put("multihop_nodes",refs);assets.put("shadowsocks",new JSONObject().put("fixture","native transport is not executed"));}
  return new JSONObject().put("profileSchemaVersion",4).put("nodeProofId",proof).put("selectedRouterID","node-"+position).put("routerProfiles",new JSONArray().put(profile)).put("profiles",assets).put("modes",new JSONArray().put(new JSONObject().put("id","wg")).put(new JSONObject().put("id","shadowsocks")));
 }
 static final class Fixture implements AutoCloseable {
  final Path root;final Context context;final AndroidNodeStore nodes;final AndroidStandardExitStore exits;
  final AndroidNodeStore.ChainCapture captured;final boolean imported;
  Fixture(Path parent,boolean imported)throws Exception{
   this.imported=imported;root=Files.createTempDirectory(parent,"history-");context=new Context(root.toFile());nodes=new AndroidNodeStore(context);exits=new AndroidStandardExitStore(context);
   JSONArray refs=new JSONArray();for(int i=0;i<3;i++)refs.put(new JSONObject().put("id",imported&&i==1?"middle":"node-"+i).put("mode",i==2||imported&&i==1?"shadowsocks":"wg"));
   if(imported){AndroidStandardExitStore.Entry e=new AndroidStandardExitStore.Entry();e.id="middle";e.name="Original imported";e.protocol="shadowsocks";e.method="2022-blake3-aes-256-gcm";e.secret=Base64.getEncoder().encodeToString(new byte[32]);e.server="8.8.8.8";e.serverPort=443;e.expectedPublicIp="8.8.4.4";exits.save(e);}
   for(int i=0;i<3;i++)if(!imported||i!=1)nodes.importBundle(bytes(bundle(i,refs).toString()));
   captured=nodes.captureChain(nodes.activeId());captured.requireCurrent();
  }
  Path history(boolean execution){return root.resolve(execution?AndroidOrderedExecutionLatencyStore.FILE_NAME:AndroidOrderedLatencyStore.FILE_NAME);}
  File source(int position){return nodes.file(captured.members.get(position).id);}
  public void close()throws Exception{try(var stream=Files.walk(root)){for(Path p:stream.sorted(Comparator.reverseOrder()).toList())Files.deleteIfExists(p);}}
 }
 static AndroidOrderedLatencyStore.Record record(String request,boolean execution)throws Exception{
  JSONObject dist=new JSONObject().put("samples",50).put("min_ms",1).put("median_ms",2).put("average_ms",2).put("p90_ms",3).put("max_ms",4).put("jitter_ms",1);
  JSONObject bench=new JSONObject().put("schema",1).put("measurement",AndroidOrderedLatencyStore.PRIVATE).put("endpoint","").put("attempts",50).put("failed",0).put("distribution",dist).put("trimmed_mean_ms",2);
  JSONObject result=new JSONObject().put("node_id","node-0").put("role","entry").put("kind","private-node").put("label",execution?"Cumulative server path through node 1 of 3":"Cumulative path through node 1 of 3").put("ready",true).put("benchmark",bench);
  String raw=new JSONObject().put("schema",1).put("source_sha256","9".repeat(64)).put("config_sha256","8".repeat(64)).put("generation_sha256","7".repeat(64)).put("position",0).put("node_id","node-0").put("request_id",request).put("measured_at",System.currentTimeMillis()).put("result",result).toString();
  return execution?new AndroidOrderedLatencyStore.Record(raw,"server"):new AndroidOrderedLatencyStore.Record(raw);
 }
 static void save(Fixture f,String request,boolean execution,AndroidOrderedLatencyStore.Guard guard)throws Exception{
  var receipt=record(request,execution);
  if(!execution){AndroidOrderedLatencyStore.save(f.context,receipt,guard);return;}
  JSONArray members=new JSONArray();for(int i=0;i<3;i++)members.put(new JSONObject().put("node_id",f.captured.members.get(i).profileId).put("position",i).put("role",i==0?"entry":i==2?"exit":"intermediate").put("kind",f.captured.members.get(i).imported?"public-path":"private-node"));
  var capture=new AndroidOrderedExecutionLatencyCapture(new JSONObject().put("schema",1).put("source_sha256",receipt.source).put("config_sha256",receipt.config).put("generation_sha256",receipt.generation).put("selected_execution","server").put("nodes",members).toString());
  AndroidOrderedExecutionLatencyStore.save(f.context,new AndroidOrderedExecutionLatencyStore.Entry("a".repeat(64),"b".repeat(64),"server",capture,receipt),guard);
 }
 static void publication(Fixture f,String request,boolean execution)throws Exception{
  AndroidOrderedLatencySourceTransaction.run(f.captured,source->{source.require(f.captured);save(f,request,execution,()->source.require(f.captured));return null;});
 }
 static void monitors(Path root)throws Exception{
  for(String kind:List.of("node-instance","node-global","imported-instance","imported-global"))try(Fixture f=new Fixture(root,true)){
   Object held=kind.equals("node-instance")?f.nodes:kind.equals("node-global")?field(AndroidNodeStore.class,"STORE_LOCK"):kind.equals("imported-instance")?f.exits:field(AndroidStandardExitStore.class,"STORE_LOCK");
   CountDownLatch entered=new CountDownLatch(1),release=new CountDownLatch(1),done=new CountDownLatch(1);AtomicReference<Throwable> error=new AtomicReference<>();
   Thread reader=new Thread(()->{try{synchronized(held){if(kind.startsWith("node"))f.nodes.snapshotSelection();else f.exits.list();entered.countDown();if(!release.await(8,TimeUnit.SECONDS))throw new AssertionError("fixture source holder did not release");}}catch(Throwable t){error.set(t);}},"original-source-reader");
   Thread writer=new Thread(()->{try{publication(f,"1".repeat(32),false);}catch(Throwable t){error.set(t);}finally{done.countDown();}},"actual-history-writer");
   boolean forbidden=false,completedWhileHeld=false;reader.start();try{
    check(entered.await(5,TimeUnit.SECONDS),"actual source reader did not hold "+kind);writer.start();long end=System.nanoTime()+TimeUnit.SECONDS.toNanos(5);
    while(done.getCount()!=0&&System.nanoTime()<end){ThreadInfo info=ManagementFactory.getThreadMXBean().getThreadInfo(writer.getId());LockInfo lock=info==null?null:info.getLockInfo();
     if(info!=null&&info.getThreadState()==Thread.State.BLOCKED&&info.getLockOwnerId()==reader.getId()&&lock!=null&&lock.getIdentityHashCode()==System.identityHashCode(held)){forbidden=true;break;}
     java.util.concurrent.locks.LockSupport.parkNanos(TimeUnit.MILLISECONDS.toNanos(1));
    }
    completedWhileHeld=done.getCount()==0;
   }finally{release.countDown();reader.join(6000);if(writer.getState()!=Thread.State.NEW)writer.join(6000);}
   check(!reader.isAlive()&&!writer.isAlive(),"source/history fixture failed to join original threads");
   check(!forbidden,"history reentered original mutation monitor: "+kind);
   check(completedWhileHeld,"history waited for the original source monitor: "+kind);
   check(error.get()==null&&done.getCount()==0&&Files.isRegularFile(f.history(false)),"immutable history did not finish under held "+kind+": "+error.get());
  }
 }
 static void scope(Path root)throws Exception{try(Fixture f=new Fixture(root,false)){
  reject(()->f.captured.historyReadback(),"history capability escaped missing private monitors");
  var other=f.nodes.captureChain(f.nodes.activeId());final AndroidNodeStore.HistoryReadback[] retained=new AndroidNodeStore.HistoryReadback[1];
  AndroidOrderedLatencySourceTransaction.run(f.captured,source->{retained[0]=source;source.require(f.captured);reject(()->source.require(other),"history capability borrowed another capture");
   AtomicBoolean refused=new AtomicBoolean();Thread t=new Thread(()->{try{source.require(f.captured);}catch(Exception expected){refused.set(true);}},"foreign-readback-thread");t.start();t.join(3000);check(!t.isAlive()&&refused.get(),"history capability borrowed another thread");return null;});
  synchronized(AndroidHomeStateStore.class){synchronized(AndroidPrivateFileStore.class){reject(()->retained[0].require(f.captured),"history capability survived its successful callback");}}
  reject(()->AndroidOrderedLatencySourceTransaction.run(f.captured,source->{retained[0]=source;throw new IOException("original callback failure");}),"history callback failure was swallowed");
  synchronized(AndroidHomeStateStore.class){synchronized(AndroidPrivateFileStore.class){reject(()->retained[0].require(f.captured),"history capability survived its failed callback");}}
 }}
 static void sources(Path root)throws Exception{
  for(String fault:List.of("paired","active","deleted","selection","imported","imported-deleted"))try(Fixture f=new Fixture(root,true)){
   if(fault.equals("paired")){File file=f.source(0);AndroidPrivateFileStore.write(file,bytes(Files.readString(file.toPath())+" "),AndroidNodeStore.MAX_BUNDLE);}
   if(fault.equals("active")){Path file=f.root.resolve(AndroidNodeStore.ACTIVE_BUNDLE);AndroidPrivateFileStore.write(file.toFile(),bytes(Files.readString(file)+" "),AndroidNodeStore.MAX_BUNDLE);}
   if(fault.equals("deleted"))AndroidPrivateFileStore.remove(f.source(0),AndroidNodeStore.MAX_BUNDLE);
   if(fault.equals("selection"))f.context.getSharedPreferences("router-vpn",0).edit().putString("active_node_id_v1",f.captured.members.get(0).id).apply();
   if(fault.equals("imported")){var e=f.exits.get("middle");e.name="replacement imported source";f.exits.save(e);}
   if(fault.equals("imported-deleted"))f.exits.remove("middle");
   reject(()->publication(f,"2".repeat(32),false),"history accepted changed source: "+fault);check(!Files.exists(f.history(false)),"changed source wrote history: "+fault);
  }
 }
 static void epochs(Path root)throws Exception{
  try(Fixture f=new Fixture(root,false)){f.nodes.select(f.captured.members.get(0).id);f.nodes.select(f.captured.control.id);reject(()->publication(f,"3".repeat(32),false),"history accepted source change-away-back epoch");}
  try(Fixture f=new Fixture(root,true)){f.exits.save(f.exits.get("middle"));reject(()->publication(f,"4".repeat(32),false),"history accepted imported identical-byte publication epoch");}
 }
 static void history(Path root,boolean execution)throws Exception{try(Fixture f=new Fixture(root,true)){
  publication(f,"5".repeat(32),execution);byte[] first=Files.readAllBytes(f.history(execution));
  check(new JSONObject(new String(first,StandardCharsets.UTF_8)).getJSONArray("records").length()==1,"original history record missing");
  reject(()->publication(f,"5".repeat(32),execution),"same request was republished");check(Arrays.equals(first,Files.readAllBytes(f.history(execution))),"duplicate request replaced history");
  check(!Files.exists(f.history(!execution)),"ordinary and execution history shared a file");
 }}
 static void rollback(Path root)throws Exception{
  for(boolean execution:List.of(false,true))for(String fault:List.of("guard","source","replacement"))try(Fixture f=new Fixture(root,true)){
   publication(f,"6".repeat(32),execution);byte[] original=Files.readAllBytes(f.history(execution)),replacement=bytes("{\"independent\":true}");AtomicInteger guards=new AtomicInteger();
   reject(()->AndroidOrderedLatencySourceTransaction.run(f.captured,source->{save(f,"7".repeat(32),execution,()->{
    if(guards.incrementAndGet()==3){if(fault.equals("source")){File file=f.source(0);AndroidPrivateFileStore.write(file,bytes(Files.readString(file.toPath())+" "),AndroidNodeStore.MAX_BUNDLE);}else if(fault.equals("replacement"))AndroidPrivateFileStore.write(f.history(execution).toFile(),replacement,AndroidOrderedLatencyStore.MAX_STORE);else throw new IOException("late original guard refusal");}
    source.require(f.captured);if(guards.get()==3&&fault.equals("replacement"))throw new IOException("later writer owns history");
   });return null;}),"late history guard was omitted: "+fault);
   check(guards.get()==3,"history lost original three guard boundaries");
   check(Arrays.equals(fault.equals("replacement")?replacement:original,Files.readAllBytes(f.history(execution))),"history rollback overwrote another writer: "+fault);
  }
 }
 public static void main(String[] args)throws Exception{
  Path root=Path.of(args[0]);Files.createDirectories(root);String family=args.length==2?args[1]:"all";
  Map<String,Integer> expected=Map.of("monitors",20,"scope",6,"sources",12,"epochs",2,"ordinary",4,"execution",4,"rollback",18);
  for(String name:List.of("monitors","scope","sources","epochs","ordinary","execution","rollback"))if(family.equals("all")||family.equals(name)){
   int before=checks;
   switch(name){case "monitors":monitors(root);break;case "scope":scope(root);break;case "sources":sources(root);break;case "epochs":epochs(root);break;case "ordinary":history(root,false);break;case "execution":history(root,true);break;case "rollback":rollback(root);break;default:throw new AssertionError(name);}
   if(checks-before!=expected.get(name))throw new AssertionError("The real-store fixture lost its original check inventory: "+name);
   System.out.println("PASS original-history-source "+name);
  }
  System.out.println("Android ordered history source: "+checks+" actual store/monitor checks PASS (native proof boundary explicit)");
 }
}
'''


def source_manifest():
    paths = {Path(__file__).relative_to(ROOT), Path("go.mod"),
             Path("android/test_android_node_usage.py"), Path("android/test_android_startup_policy.py")}
    if os.path.lexists(ROOT / "go.sum"):
        paths.add(Path("go.sum"))
    paths.update(Path("android/app/src/main/java/com/eabusham/routervpn") / (name + ".java")
                 for name in (*ACTUAL, "AndroidExternalPolicy", "AndroidNodeChainCapture", "AndroidNodeChainExecutionCapture", "AndroidNodeChainSession"))
    for directory in ("internal", "mobile"):
        paths.update(path.relative_to(ROOT) for path in (ROOT / directory).rglob("*.go"))
    result = {}
    for path in sorted(paths):
        source = ROOT / path
        if source.is_symlink() or not source.is_file():
            raise RuntimeError("Original fixture input is not a regular file: " + str(path))
        result[str(path)] = hashlib.sha256(source.read_bytes()).hexdigest()
    return result


def fixture_sources():
    usage = ROOT / "android/test_android_node_usage.py"
    startup = ROOT / "android/test_android_startup_policy.py"
    result = {"android/content/Context.java": CONTEXT, "android/content/SharedPreferences.java": PREFS,
              "android/content/MemoryPreferences.java": MEMORY, "android/system/Os.java": literal(usage, "OS"),
              "android/system/OsConstants.java": "package android.system;public final class OsConstants{public static final int S_IFMT=0170000,S_IFREG=0100000,S_IFDIR=0040000,ENOENT=2;}",
              "android/system/StructStat.java": "package android.system;public final class StructStat{public final int st_mode;public final long st_dev,st_ino,st_size;public StructStat(int m,long d,long i,long s){st_mode=m;st_dev=d;st_ino=i;st_size=s;}}",
              "android/system/ErrnoException.java": "package android.system;public final class ErrnoException extends Exception{public final int errno;public ErrnoException(String message,int value){super(message);errno=value;}}",
              "android/util/Base64.java": "package android.util;public final class Base64{public static final int DEFAULT=0;public static byte[] decode(String value,int flags){return java.util.Base64.getMimeDecoder().decode(value);}}",
              "com/wireguard/android/backend/Tunnel.java": "package com.wireguard.android.backend;public interface Tunnel{enum State{UP,DOWN}}",
              "org/amnezia/awg/backend/Tunnel.java": "package org.amnezia.awg.backend;public interface Tunnel{enum State{UP,DOWN}}",
              "io/nekohasekai/libbox/Libbox.java": literal(startup, "PRIVATE_JSON_JAVA"),
              APP + "OrderedHistorySourceTest.java": HARNESS}
    # History transactions never open a native chain. Preserve that refusal
    # while compiling the current shipping NodeStore constructor call.
    libbox = result["io/nekohasekai/libbox/Libbox.java"]
    opening = "public final class Libbox {"
    assert libbox.count(opening) == 1
    result["io/nekohasekai/libbox/Libbox.java"] = libbox.replace(opening, opening + \
        '\n public static String routerNodeChainImportedOpenVPNMemberInput(String source,String capture){throw new AssertionError("Native OpenVPN chain outside immutable readback fixture");}', 1)
    policy = (JAVA / "AndroidExternalPolicy.java").read_text()
    start = policy.index("    private static final Set<String> POLICY =")
    constants = policy[start:policy.index(";", start) + 1]
    methods = "\n".join(block(policy, signature) for signature in
                        ("    static boolean supports(", "    static String protocol(", "    static void checkPolicy(", "    private static boolean bounded("))
    result[APP + "Boundaries.java"] = BOUNDARY.replace(" // PURE_POLICY_SOURCE", " static final int MAX_CAPTURE=8*1024*1024;\n" + constants + methods).replace(
        " // CAPTURE_TYPE_SOURCE", block(policy, "    static final class Captured {"))
    # Capture shape is pure shipping validation, not native chain admission.
    # Keep the original shape and candidate preview used by NodeStore; the native boundary above
    # still refuses construction and grants no runtime/history ownership.
    capture = (JAVA / "AndroidNodeChainCapture.java").read_text()
    shape = "\n".join(block(capture, signature) for signature in
                      ("    static int sourceSchema(", "    static void requireLiteralImportedSS(",
                       "    static boolean pairedStreamInterior(", "    static void requireCompleteShape(", "    static boolean responsePrefix("))
    result[APP + "AndroidNodeChainCapture.java"] = ("package com.eabusham.routervpn;\n"
        "import java.util.List;\nfinal class AndroidNodeChainCapture {\n" + shape + '\nstatic String memberInput(AndroidNodeStore.ChainSource source,String mode,org.json.JSONObject profile)throws Exception{throw new IllegalStateException("No native candidate compiler in the source transaction fixture.");}\n}\n')
    for name in ACTUAL:
        result[APP + name + ".java"] = (JAVA / (name + ".java")).read_text()
    return result


def controls(originals):
    node = APP + "AndroidNodeStore.java"
    helper = APP + "AndroidOrderedLatencySourceTransaction.java"
    history_body = block(originals[node], "    private void requireHistorySource(")
    assert history_body.count("captured.generation != selectionGeneration") == 2
    return (
        ("old-source-lock", node, "captured.owner.requireHistorySource(captured);", "captured.owner.requireChainCapture(captured);", "monitors", "history reentered original mutation monitor: node-instance"),
        ("imported-mutation-lock", node, "AndroidStandardExitStore.snapshot(AndroidStandardExitStore.capturedEntry(context,source.id))", "AndroidStandardExitStore.snapshot(new AndroidStandardExitStore(context).get(source.id))", "monitors", "history reentered original mutation monitor: imported-global"),
        ("borrowed-capture", node, "captured != expected", "false", "scope", "history capability borrowed another capture"),
        ("unrevoked-scope", helper, "                    source.close();", "                    /* omitted original readback retirement */", "scope", "history capability survived its successful callback"),
        ("publication-epoch", node, history_body, history_body.replace("captured.generation != selectionGeneration", "false"), "epochs", "history accepted source change-away-back epoch"),
    )


def main():
    if os.name != "posix" or not Path("/proc/self/fd").is_dir():
        raise RuntimeError("The actual Unix private-file fixture requires Linux /proc")
    jar = Path(os.environ.get("ANDROID_JSON_JAR", "/usr/share/java/com.android.json.jar")).resolve(strict=True)
    tools = {name: Path(shutil.which(name) or "").resolve(strict=True) for name in ("go", "javac", "java")}
    if not jar.is_file() or jar.is_symlink() or any(not path.is_file() for path in tools.values()):
        raise RuntimeError("Original JSON and compiler tool files are required")
    identities = {str(path): hashlib.sha256(path.read_bytes()).hexdigest() for path in (*tools.values(), jar)}
    before = source_manifest()
    originals = fixture_sources()
    with tempfile.TemporaryDirectory(prefix="routervpn-history-locks-") as temporary:
        work = Path(temporary)
        with tempfile.TemporaryDirectory(prefix=".history-json-", dir=ROOT) as go_directory:
            go_source = Path(go_directory) / "main.go"
            go_source.write_text(literal(ROOT / "android/test_android_startup_policy.py", "PRIVATE_JSON_GO"))
            validator = work / "private-json"
            subprocess.run([str(tools["go"]), "build", "-p", "1", "-o", str(validator), str(go_source)], cwd=ROOT, check=True, timeout=120)
        validator_hash = hashlib.sha256(validator.read_bytes()).hexdigest()
        src, classes = work / "source", work / "classes"
        for path, value in originals.items():
            target = src / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(value)
        command = [str(tools["javac"]), "-J-Xmx512m", "-J-XX:ActiveProcessorCount=1", "--release", "17", "-encoding", "UTF-8", "-proc:none", "-cp", str(jar), "-d", str(classes), *map(str, sorted(src.rglob("*.java")))]
        runtime = [str(tools["java"]), "-Xmx384m", "-XX:ActiveProcessorCount=1", "--add-opens=java.base/java.io=ALL-UNNAMED", "-Dfixture.privatejson=" + str(validator), "-cp", os.pathsep.join((str(classes), str(jar))), "com.eabusham.routervpn.OrderedHistorySourceTest", str(work / "data")]
        subprocess.run(command, check=True, timeout=60)
        result = subprocess.run(runtime, capture_output=True, text=True, timeout=90)
        assert result.returncode == 0, result.stdout + result.stderr
        verdicts = [line.removeprefix("PASS original-history-source ") for line in result.stdout.splitlines() if line.startswith("PASS original-history-source ")]
        assert verdicts == list(FAMILIES), (verdicts, result.stdout, result.stderr)
        assert result.stdout.splitlines()[-1] == "Android ordered history source: 66 actual store/monitor checks PASS (native proof boundary explicit)", (result.stdout, result.stderr)
        print(result.stdout.strip(), flush=True)
        accepted = []
        for name, path, old, new, family, witness in controls(originals):
            assert originals[path].count(old) == 1, (name, path)
            target = src / path
            target.write_text(originals[path].replace(old, new, 1))
            try:
                subprocess.run(command, check=True, timeout=45)
                broken = subprocess.run([*runtime, family], capture_output=True, text=True, timeout=45)
            finally:
                target.write_text(originals[path])
            assert broken.returncode == 1 and witness in broken.stderr, (name, broken.returncode, broken.stdout, broken.stderr)
            accepted.append(name)
            print("Rejected original history source control: " + name, flush=True)
        assert source_manifest() == before, "Original source changed during real-store fixture"
        assert hashlib.sha256(validator.read_bytes()).hexdigest() == validator_hash, "Original private parser changed"
        assert all(hashlib.sha256(Path(path).read_bytes()).hexdigest() == value for path, value in identities.items()), "Original fixture tool changed"
        receipt = os.environ.get("ROUTERVPN_ORDERED_HISTORY_LOCK_RECEIPT")
        if receipt:
            Path(receipt).write_text(json.dumps({"schema": 1, "families": verdicts, "controls": accepted,
                "sources": before, "tools": identities, "private_json_image_sha256": validator_hash,
                "actual_private_store_and_monitors": True, "native_proof_or_device_acceptance": False}, sort_keys=True, indent=2) + "\n")


if __name__ == "__main__":
    main()
