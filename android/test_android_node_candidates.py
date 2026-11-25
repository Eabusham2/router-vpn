#!/usr/bin/env python3
"""Shipping candidate catalog/result/transaction against real stores and Go sources.

The native measurement boundary is a deterministic lifecycle double. Encrypted
prefix and fifty-socket acceptance belongs to the pinned native bridge tests.
"""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import test_android_connection_profiles as profiles
import test_android_node_chain_capture as chain
from typed_candidate_fixture_boundary import install_unavailable

ROOT = Path(__file__).resolve().parents[1]
JAVA = ROOT / 'android/app/src/main/java/com/eabusham/routervpn'
ORIGINAL_PREPARE = chain.prepare_sources
ORIGINAL_COMPILER = chain.compiler_source


FRAME_HELPER = r"""
func fixtureSelectedResponsePosition(source, position string) (string, error) {
 var header struct{ Schema int }
 if err := json.Unmarshal([]byte(source), &header); err != nil { return "", err }
 var prep *mobilemultihop.NodeChainExecutionPreparation
 var err error
 if header.Schema == 6 {
  prep, err = mobilemultihop.ParseNodeChainMultipleImportedExecutionPreparation(source)
 } else {
  prep, err = mobilemultihop.ParseNodeChainExecutionPreparation(source)
 }
 if err != nil { return "", err }
 var index int
 if _, err := fmt.Sscan(position, &index); err != nil { return "", err }
 return fmt.Sprint(prep.SupportsCompareLocalResponseCandidate(index)), nil
}

func fixtureCandidateFrames(plan interface{ MetadataPage(int32) string }) ([]string,error) {
 var frames []string
 for offset:=0;;{
  raw:=plan.MetadataPage(int32(offset))
  var page struct {
   Schema int `json:"schema"`
   Total int `json:"target_total"`
   Targets []json.RawMessage `json:"targets"`
  }
  if err:=json.Unmarshal([]byte(raw),&page);err!=nil{return nil,err}
  frames=append(frames,raw);offset+=len(page.Targets)
  if page.Schema==1||offset==page.Total{return frames,nil}
  if len(page.Targets)==0||offset>page.Total{return nil,fmt.Errorf("invalid original candidate frame")}
 }
}
"""

def compiler(source):
    return ORIGINAL_COMPILER(source).replace('case len(args)==2:', '''case len(args)==3&&args[0]=="selected-response-position":result,err=fixtureSelectedResponsePosition(args[1],args[2]);case len(args)==3&&args[0]=="candidate-supported-metric":result=fmt.Sprint(mobilemultihop.NodeChainCandidateInputSupportedForMeasurement(args[1],args[2]));case len(args)==3&&(args[0]=="candidate-metric"||args[0]=="candidate-proof"):var p *mobilemultihop.NodeChain;p,err=mobilemultihop.ParseNodeChainLaunchInput(args[1]);if err==nil{var pos int;_,err=fmt.Sscan(args[2],&pos);if err==nil{result=p.CandidatePrefixMeasurement(pos);if args[0]=="candidate-proof"&&result!=""{var b []byte;b,err=json.Marshal(p.ProofInventory()[pos]);result=string(b)}}};case len(args)==2&&args[0]=="candidate-supported":result=fmt.Sprint(mobilemultihop.NodeChainCandidateInputSupported(args[1]));case len(args)==4&&(args[0]=="candidate-metadata"||args[0]=="candidate-frames"):var plan *mobilemultihop.NodeChain;plan,err=mobilemultihop.ParseNodeChainLaunchInput(args[1]);if err==nil{var position int;_,err=fmt.Sscan(args[2],&position);if err==nil{var captured *mobilemultihop.NodeChainCandidatePlan;captured,err=plan.NewCandidatePlan(position,args[3]);if err==nil{result=captured.Metadata();if args[0]=="candidate-frames"{var frames []string;frames,err=fixtureCandidateFrames(captured);if err==nil{var encoded []byte;encoded,err=json.Marshal(map[string]any{"frames":frames,"complete":json.RawMessage(result)});result=string(encoded)}}}}};case len(args)==2:''') + FRAME_HELPER


SESSION = '''package com.eabusham.routervpn;
final class AndroidNodeChainSession {
 static AndroidNodeChainSession retained;static AndroidNodeChainSession retained(){return retained;}
 final AndroidNodeStore.ChainCapture source;final AndroidNodeChainCapture capture;
 final AndroidNodeCandidatePrefixCapture candidatePrefix=null;
 io.nekohasekai.libbox.RouterNodeChainExecution execution;
 io.nekohasekai.libbox.RouterNodeChainExecution candidateExecutionOwner()throws Exception{requireCurrent();return execution;}
 io.nekohasekai.libbox.CommandServer server=new io.nekohasekai.libbox.CommandServer();boolean current=true;
 AndroidNodeChainSession(AndroidNodeStore.ChainCapture source)throws Exception{this(source,-1);}
 AndroidNodeChainSession(AndroidNodeStore.ChainCapture source,int purpose)throws Exception{this.source=source;capture=AndroidNodeChainCapture.compile(source,purpose);retained=this;}
 AndroidNodeChainSession(AndroidNodeStore.ChainCapture source,Object owner)throws Exception{this.source=source;source.bindSelectedCandidatePurpose(owner,()->current);capture=AndroidNodeChainCapture.compileSelectedCandidateDraft(source,owner);retained=this;}
 void requireCurrent()throws Exception{source.requireCurrent();if(!current)throw new IllegalStateException("Retired native session/network");}
 io.nekohasekai.libbox.CommandServer candidateServer()throws Exception{requireCurrent();return server;}
}'''

NATIVE = r'''package io.nekohasekai.libbox;
import org.json.*;
public final class RouterNodeChainCandidateMeasurement {
 public static volatile boolean holdClose,factoryFailure;public static volatile int closeAttempts;public static volatile RouterNodeChainCandidateMeasurement last;
 private static final java.util.IdentityHashMap<RouterNodeChain,RouterNodeChainCandidateMeasurement> slots=new java.util.IdentityHashMap<>();
 final RouterNodeChain owner;final String info;final RouterNodeChainCandidateCatalog guard;String original="";String request="",id="";boolean closed,prepareAttempted,prepared;
 RouterNodeChainCandidateMeasurement(RouterNodeChain plan,int prefix,String inventory,RouterNodeChainCandidateCatalog guard)throws Exception{
  info=Libbox.call("candidate-metadata",plan.launchInput(),Integer.toString(prefix),inventory);this.guard=guard;owner=plan;
  synchronized(slots){if(slots.containsKey(plan))throw new IllegalStateException("Original candidate reservation remains owned");slots.put(plan,this);last=this;}
 }
 public void prepare()throws Exception{
  synchronized(slots){if(closed||slots.get(owner)!=this||prepareAttempted)throw new IllegalStateException("Foreign or repeated ordinary preparation");prepareAttempted=true;}
  String captured=guard.currentInventorySHA256();if(factoryFailure)throw new IllegalStateException("late original callback");
  if(captured.isEmpty())throw new IllegalStateException("Original candidate catalog retired");
  synchronized(slots){if(closed||slots.get(owner)!=this)throw new IllegalStateException("Retired ordinary preparation");original=captured;prepared=true;}
 }
 public boolean isClosed(){synchronized(slots){return closed;}}
 private void requirePrepared(){synchronized(slots){if(closed||slots.get(owner)!=this||!prepared)throw new IllegalStateException("Original ordinary candidate did not prepare");}}
 public volatile long metadataDelayMS;
 public String metadataPage(int offset){return "";}public String metadata(){return info;}public String captureSHA256()throws Exception{return new JSONObject(info).getString("capture_sha256");}
 public void start(String request,String id){requirePrepared();this.request=request;this.id=id;}
 public void cancel(String request){}public void drain(String request){}
 public void close()throws Exception{synchronized(slots){RouterNodeChainCandidateMeasurement retained=slots.get(owner);if(retained!=null&&retained!=this)throw new IllegalStateException("Foreign ordinary cleanup receipt");if(closed)return;if(retained!=this)throw new IllegalStateException("Missing original ordinary cleanup receipt");closeAttempts++;if(holdClose)throw new IllegalStateException("Original native callback not joined");closed=true;slots.remove(owner);}}
 public String statusJSON()throws Exception{requirePrepared();
  JSONObject meta=new JSONObject(info);String source="";JSONArray targets=meta.getJSONArray("targets");for(int i=0;i<targets.length();i++)if(id.equals(targets.getJSONObject(i).getString("id")))source=targets.getJSONObject(i).getString("source_sha256");
  long now=System.currentTimeMillis();JSONObject distribution=new JSONObject().put("samples",50).put("min_ms",1).put("median_ms",2).put("average_ms",2).put("p90_ms",3).put("max_ms",4).put("jitter_ms",1);
  String metric=meta.optString("measurement","routed-tcp-connect");
  JSONObject row=new JSONObject().put("node_id",id).put("role","candidate").put("kind","routed-candidate-response".equals(metric)?"private-agent-response":"tcp-connect").put("ready",true).put("benchmark",new JSONObject().put("schema",1).put("measurement",metric).put("attempts",50).put("failed",0).put("distribution",distribution).put("trimmed_mean_ms",id.startsWith("chain-")?1.5:2.5));
  boolean current=!original.isEmpty()&&original.equals(guard.currentInventorySHA256());
  return new JSONObject().put("schema",1).put("measurement",metric).put("request_id",request).put("complete",true).put("drained",true).put("stage",current?"complete":"invalidated").put("failure",current?"":"retired").put("capture_sha256",meta.getString("capture_sha256")).put("prefix_position",meta.getInt("prefix_position")).put("prefix_id",meta.getString("prefix_id")).put("candidate_id",id).put("candidate_source_sha256",source).put("measured_at",now).put("expires_at",now+120000).put("results",new JSONArray().put(row)).toString();
 }
}'''

def framed_native():
 """Forward each actual Go metadata frame through the original modeled handle.
 The private helper also returns the full target map to its native result double."""
 source=NATIVE.replace('final RouterNodeChain owner;','final java.util.Map<Integer,String> frames=new java.util.HashMap<>();final JSONObject complete;final RouterNodeChain owner;')
 old='info=Libbox.call("candidate-metadata",plan.launchInput(),Integer.toString(prefix),inventory);'
 new='''JSONObject output=new JSONObject(Libbox.call("candidate-frames",plan.launchInput(),Integer.toString(prefix),inventory));
  complete=output.getJSONObject("complete");JSONArray values=output.getJSONArray("frames");
  for(int i=0;i<values.length();i++){String raw=values.getString(i);JSONObject page=new JSONObject(raw);frames.put(page.optInt("target_offset",0),raw);}info=frames.get(0);'''
 assert source.count(old)==1
 source=source.replace('public String metadata(){return info;}','public String metadata(){if(metadataDelayMS>0)try{Thread.sleep(metadataDelayMS);}catch(InterruptedException error){Thread.currentThread().interrupt();throw new IllegalStateException(error);}return info;}')
 return source.replace(old,new).replace('public String metadataPage(int offset){return "";}','public String metadataPage(int offset){requirePrepared();return frames.getOrDefault(offset,"");}').replace('JSONObject meta=new JSONObject(info);String source="";','JSONObject meta=complete;String source="";')

HARNESS = r'''package com.eabusham.routervpn;
import java.nio.file.*;import java.nio.charset.StandardCharsets;import java.util.*;import java.util.concurrent.*;import org.json.*;import io.nekohasekai.libbox.*;
public final class NodeCandidateHarness {
 static int checks;static void check(boolean value,String message){checks++;if(!value)throw new AssertionError(message);}
 interface Work{void run()throws Exception;}static void reject(Work action,String message)throws Exception{try{action.run();}catch(Exception expected){checks++;return;}throw new AssertionError(message);}
 static NodeChainCaptureHarness.Fixture fixture(Path root)throws Exception{return new NodeChainCaptureHarness.Fixture(root,"2/");}
 static AndroidStandardExitStore.Entry custom(String method){AndroidStandardExitStore.Entry entry=new AndroidStandardExitStore.Entry();entry.id="1234567890abcdef1234567890abcdef";entry.name="Custom candidate";entry.protocol="shadowsocks";entry.server="198.51.100.76";entry.serverPort=443;entry.expectedPublicIp="203.0.113.76";entry.method=method;entry.secret=Base64.getEncoder().encodeToString(new byte[method.contains("aes-128")?16:32]);return entry;}
 interface PrefixCheck{void check(AndroidNodeChainCapture original,String inventory,int count)throws Exception;}
 static void largeCatalog(Path root)throws Exception{largeCatalog(root,null);}
 static void largeCatalog(Path root,PrefixCheck extra)throws Exception{
  long started=System.nanoTime();
  var f=fixture(root);var exits=new AndroidStandardExitStore(f.context);Set<String> expected=new HashSet<>();
  var expanded=new ArrayList<AndroidStandardExitStore.Entry>();
  for(int i=0;i<513;i++){
   var entry=custom("2022-blake3-aes-256-gcm");entry.id=String.format("linked-candidate-original-profile-%04d",i);entry.name="Same display name";expected.add(entry.id);
   if(i<129)exits.save(entry);else expanded.add(entry);
  }
  List<AndroidStandardExitStore.Entry> original=exits.list();check(original.size()>=129,"normal saves dropped the first 129 entries");
  original.addAll(expanded);
  // Serialize the full, validated fixture once using the same publisher as save.
  var publish=AndroidStandardExitStore.class.getDeclaredMethod("writeStore",List.class);publish.setAccessible(true);publish.invoke(exits,original);
  check(exits.list().size()==original.size(),"complete normal store did not retain all qualified candidate inputs");
  var session=new AndroidNodeChainSession(f.profiles.currentOrderedPath());var catalog=new AndroidNodeCandidateCatalog(f.context,session,0);
  Set<String> captured=new HashSet<>();for(var row:catalog.rows)if(!row.input.isEmpty())captured.add(row.id);
  check(captured.containsAll(expected),"large Android catalog omitted a linked source after candidate 64");
  var nativeOwner=Libbox.routerNodeChainNewCandidateMeasurement(session.capture.plan,session.server,0,catalog.inventory,catalog);
  try{nativeOwner.prepare();long deadline=AndroidNodeCandidateMetadata.observationDeadline();String first=nativeOwner.metadata();check(new JSONObject(first).getInt("schema")==2&&first.getBytes(java.nio.charset.StandardCharsets.UTF_8).length<=12*1024,"large native inventory did not use bounded pages");
   var offsets=new ArrayList<Integer>();
   JSONObject meta=AndroidNodeCandidateMetadata.read(first,offset->{offsets.add(offset);return nativeOwner.metadataPage(offset);},captured.size(),deadline);
   int projectedBytes=meta.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8).length;
   check(offsets.size()>1&&offsets.get(0)>0&&projectedBytes>64*1024,"large Android inventory did not cross established frame budget");
   System.out.println("Verified "+(offsets.size()+1)+" native metadata pages and "+projectedBytes+" public bytes");
   for(String fault:List.of("offset","digest","reorder","duplicate","foreign","oversize","eof","empty","non-ascii")){
    reject(()->AndroidNodeCandidateMetadata.read(first,offset->{
     String frame=nativeOwner.metadataPage(offset);JSONObject changed=new JSONObject(frame);JSONArray rows=changed.getJSONArray("targets");
     switch(fault){
      case "offset":changed.put("target_offset",offset+1);break;
      case "digest":changed.put("targets_sha256","0".repeat(64));break;
      case "reorder":JSONObject left=rows.getJSONObject(0);rows.put(0,rows.getJSONObject(1));rows.put(1,left);break;
      case "duplicate":rows.put(0,new JSONObject(first).getJSONArray("targets").getJSONObject(0));break;
      case "foreign":changed.put("capture_sha256","f".repeat(64));break;
      case "non-ascii":rows.getJSONObject(0).put("id","alternate-\u2603");break;
      case "oversize":return frame+" ".repeat(12*1024);
      case "eof":return "";
      case "empty":changed.put("targets",new JSONArray());break;
     }return changed.toString();
    },captured.size(),AndroidNodeCandidateMetadata.observationDeadline()),"bounded Android metadata accepted "+fault);
   }
   reject(()->AndroidNodeCandidateMetadata.read(first,nativeOwner::metadataPage,captured.size(),System.nanoTime()-1),"expired page observation was renewed");
   Set<String> ids=new HashSet<>();JSONArray targets=meta.getJSONArray("targets");for(int i=0;i<targets.length();i++)ids.add(targets.getJSONObject(i).getString("id"));
   check(ids.equals(captured),"large Android metadata omitted or substituted an original source");
   // Execute the production observation method with its real complete catalog
   // and original Go frames. The native boundary alone delays the next read.
   var constructor=AndroidNodeCandidateMeasurement.class.getDeclaredConstructor(AndroidNodeCandidateCatalog.class,AndroidNodeCandidateMeasurement.Callback.class);constructor.setAccessible(true);
   var observation=constructor.newInstance(catalog,null);
   var ownerType=Class.forName("com.eabusham.routervpn.AndroidNodeCandidateMeasurement$NativeOwner");
   var ownerConstructor=ownerType.getDeclaredConstructor(RouterNodeChainCandidateMeasurement.class);ownerConstructor.setAccessible(true);
   var ownerField=AndroidNodeCandidateMeasurement.class.getDeclaredField("nativeOwner");ownerField.setAccessible(true);ownerField.set(observation,ownerConstructor.newInstance(nativeOwner));
   var read=AndroidNodeCandidateMeasurement.class.getDeclaredMethod("requireMetadata");read.setAccessible(true);
   JSONObject initial=(JSONObject)read.invoke(observation);
   check(initial.getJSONArray("targets").length()==captured.size(),"production observation did not retain the complete paged catalog");
   check(read.invoke(observation)==initial,"unchanged native commitment did not reuse the original verified target map");
   nativeOwner.metadataDelayMS=1600;
   boolean lateRefused=false;
   try{read.invoke(observation);}catch(java.lang.reflect.InvocationTargetException late){if(!(late.getCause() instanceof IllegalArgumentException)||!late.getCause().getMessage().contains("Candidate metadata did not preserve"))throw late;lateRefused=true;}
   finally{nativeOwner.metadataDelayMS=0;}
   check(lateRefused,"cached candidate metadata escaped its original observation deadline");
   for(String id:List.of("linked-candidate-original-profile-0000","linked-candidate-original-profile-0512")){String request=id.endsWith("0000")?"c".repeat(32):"d".repeat(32);nativeOwner.start(request,id);nativeOwner.drain(request);var accepted=AndroidNodeCandidateResult.capture(nativeOwner.statusJSON(),request,meta,id,"Same display name",System.currentTimeMillis());check(accepted.id.equals(id),"large Android catalog receipt used display name instead of original identity");}
  }finally{nativeOwner.close();}
  if(extra!=null)extra.check(session.capture,catalog.inventory,captured.size());
  var changed=exits.list().stream().filter(entry->entry.id.equals("linked-candidate-original-profile-0512")).findFirst().orElseThrow();changed.secret=Base64.getEncoder().encodeToString(new byte[16]);exits.save(changed);
  check(catalog.currentInventorySHA256().isEmpty(),"off-page private source change did not retire large Android catalog");
  System.out.println("Verified "+captured.size()+" captured Android targets in "+TimeUnit.NANOSECONDS.toMillis(System.nanoTime()-started)+" ms");
 }
 static void openVPNTCPCandidates(Path root)throws Exception{
  var f=fixture(root);var exits=new AndroidStandardExitStore(f.context);
  for(String network:List.of("tcp","udp")){
   var entry=new AndroidStandardExitStore.Entry();entry.id="provider-"+network;entry.name=entry.id;entry.protocol="openvpn";
   entry.server="203.0.113.20";entry.serverPort=1194;entry.expectedPublicIp="203.0.113.76";entry.username="original-provider-user";entry.password="original-provider-secret";
   entry.openVPNConfig="client\ndev tun\nproto "+network+"\nremote 203.0.113.20 1194\nauth-user-pass\nremote-cert-tls server\npeer-fingerprint "+"ab".repeat(32)+"\ntun-mtu 1280\ndata-ciphers AES-256-GCM:AES-128-GCM\n";
   entry.policy.put("start_layer","off").put("mtu_policy","manual").put("manual_mtu",1280);
   exits.save(entry);
  }
  var catalog=AndroidNodeCandidateCatalog.captureSources(f.context,f.profiles.currentOrderedPath(),0);
  var tcp=catalog.rows.stream().filter(row->row.localID.equals("provider-tcp")).findFirst().orElseThrow();
  var udp=catalog.rows.stream().filter(row->row.localID.equals("provider-udp")).findFirst().orElseThrow();
  check(tcp.reason.isEmpty()&&!tcp.input.isEmpty()&&Libbox.routerNodeChainCandidateInputSupported(tcp.input),"original OpenVPN TCP remote lost its eligible candidate");
  var member=new JSONObject(tcp.input);
  check(member.getString("kind").equals("routervpn-node-chain-openvpn-member")&&new JSONObject(member.getString("capture")).getJSONObject("profile").getJSONObject("external").getJSONObject("openvpn").getString("username").equals("original-provider-user"),"OpenVPN TCP candidate discarded its original typed source");
  check(udp.input.isEmpty()&&!udp.reason.isEmpty(),"UDP at the same original address acquired a TCP score");
  var tcpEntry=exits.list().stream().filter(entry->entry.id.equals("provider-tcp")).findFirst().orElseThrow();tcpEntry.password="replaced-private-provider";exits.save(tcpEntry);
  reject(catalog::requireSourcesCurrent,"OpenVPN candidate survived replacement of its original private credentials");
 }
 static void capturedSources(Path root)throws Exception{
  var f=fixture(root);var source=f.profiles.currentOrderedPath();
  var unopened=AndroidNodeCandidateCatalog.captureSources(f.context,source,0);unopened.requireSourcesCurrent();
  check(unopened.originalSource==source&&unopened.session==null&&unopened.server==null,"saved catalog capture acquired native authority before permission");
  check(unopened.currentInventorySHA256().isEmpty(),"unbound saved catalog lent live callback authority");
  var session=new AndroidNodeChainSession(source);reject(()->unopened.bind(session),"observed unbound catalog revived native authority");
  var catalog=AndroidNodeCandidateCatalog.captureSources(f.context,source,0);String inventory=catalog.inventory;
  reject(()->catalog.bind(new AndroidNodeChainSession(f.profiles.currentOrderedPath())),"same-byte foreign source bound captured catalog");
  catalog.bind(session);check(catalog.session==session&&catalog.server==session.server&&inventory.equals(catalog.inventory)&&catalog.inventorySHA.equals(catalog.currentInventorySHA256()),"saved catalog binding rebuilt inventory or lost exact native owner");
  reject(()->catalog.bind(session),"saved catalog bound its native owner twice");
  var pending=AndroidNodeCandidateCatalog.captureSources(f.context,source,0);Path path=f.control().file.toPath();byte[] before=Files.readAllBytes(path);
  Files.writeString(path,new String(before,StandardCharsets.UTF_8)+" ");reject(pending::requireSourcesCurrent,"prepermission source mutation was ignored");Files.write(path,before);
  reject(()->pending.bind(session),"prepermission source change-away/back revived catalog");
 }
 static void sources(Path root)throws Exception{
  for(String method:List.of("2022-blake3-aes-128-gcm","2022-blake3-aes-256-gcm","2022-blake3-chacha20-poly1305")){
   var f=new NodeChainCaptureHarness.Fixture(root,method.contains("aes-128")?"2/":method.contains("aes-256")?"2/awg-fast":"3/awg-strong");var exits=new AndroidStandardExitStore(f.context);var entry=custom(method);exits.save(entry);var unsupported=new AndroidStandardExitStore.Entry();unsupported.id="unsupported-socks";unsupported.name="Unscored SOCKS";unsupported.protocol="socks5";unsupported.server="192.0.2.90";unsupported.serverPort=1080;unsupported.expectedPublicIp="203.0.113.90";unsupported.username="u".repeat(256);unsupported.password="bounded-password";exits.save(unsupported);
   var session=new AndroidNodeChainSession(f.profiles.currentOrderedPath());var catalog=new AndroidNodeCandidateCatalog(f.context,session,0);
   check(catalog.rows.stream().anyMatch(row->row.id.equals(entry.id)&&!row.input.isEmpty()),"original three-cipher custom source was omitted");
   JSONObject inventory=new JSONObject(catalog.inventory);check(inventory.getJSONArray("inputs").length()==2,"complete paired/custom candidate inventory lost a source");
   check(catalog.inventorySHA.equals(catalog.currentInventorySHA256()),"original live catalog was rejected");
   check(catalog.rows.size()==session.source.members.size()+1&&catalog.rows.stream().anyMatch(row->row.id.equals(unsupported.id)&&row.input.isEmpty()),"unsupported transport was hidden or fabricated a TCP score");
   Path allSources=f.context.getFilesDir().toPath().resolve("standard-exits.json");byte[] originalCatalog=Files.readAllBytes(allSources);Files.writeString(allSources,new String(originalCatalog,StandardCharsets.UTF_8).replace("Unscored SOCKS","Changed unscored SOCKS"));check(catalog.currentInventorySHA256().isEmpty(),"unsupported candidate source replacement accepted");Files.write(allSources,originalCatalog);reject(catalog::requireSavedSourcesCurrent,"observed source change-away/back revived post-DOWN catalog authority");catalog=new AndroidNodeCandidateCatalog(f.context,session,0);
   Path retainedImports=allSources.resolveSibling("retained-imported-original");Files.move(allSources,retainedImports);Files.write(allSources,originalCatalog);check(catalog.currentInventorySHA256().isEmpty(),"same-byte imported container replacement revived original identity");Files.delete(allSources);Files.move(retainedImports,allSources);check(catalog.currentInventorySHA256().isEmpty(),"observed imported container replacement revived after restoring original inode");catalog=new AndroidNodeCandidateCatalog(f.context,session,0);
   byte[] old=Files.readAllBytes(f.control().file.toPath());Files.writeString(f.control().file.toPath(),new String(old,StandardCharsets.UTF_8)+" ");check(catalog.currentInventorySHA256().isEmpty(),"raw source replacement accepted");Files.write(f.control().file.toPath(),old);catalog=new AndroidNodeCandidateCatalog(f.context,session,0);
   session.current=false;check(catalog.currentInventorySHA256().isEmpty(),"retired native session/network accepted");catalog.requireSavedSourcesCurrent();check(true,"normal native retirement wrongly invalidated saved sources");session.current=true;catalog=new AndroidNodeCandidateCatalog(f.context,session,0);
   CommandServer original=session.server;session.server=new CommandServer();check(catalog.currentInventorySHA256().isEmpty(),"replaced native server accepted");session.server=original;catalog=new AndroidNodeCandidateCatalog(f.context,session,0);
   Path replaced=f.control().file.toPath(),retained=replaced.resolveSibling("retained-original");Files.move(replaced,retained);Files.write(replaced,old);check(catalog.currentInventorySHA256().isEmpty(),"same-byte replacement revived original file identity");Files.delete(replaced);Files.move(retained,replaced);check(catalog.currentInventorySHA256().isEmpty(),"observed file replacement revived after restoring original inode");catalog=new AndroidNodeCandidateCatalog(f.context,session,0);
   String saved=entry.name;entry.name="temporary";exits.save(entry);entry.name=saved;exits.save(entry);check(catalog.currentInventorySHA256().isEmpty(),"catalog change-away/back revived a capture");
  }
  var f=fixture(root);var session=new AndroidNodeChainSession(f.profiles.currentOrderedPath());reject(()->new AndroidNodeCandidateCatalog(f.context,session,1),"lazy SS prefix falsely timed destination TCP");
 }
 static void overlappingSavedSources(Path root)throws Exception{
  var f=fixture(root);new AndroidStandardExitStore(f.context).save(custom("2022-blake3-aes-256-gcm"));
  var session=new AndroidNodeChainSession(f.profiles.currentOrderedPath());var catalog=new AndroidNodeCandidateCatalog(f.context,session,0);
  Path imported=f.context.getFilesDir().toPath().resolve("standard-exits.json");byte[] original=Files.readAllBytes(imported);
  CountDownLatch reading=new CountDownLatch(1),resume=new CountDownLatch(1);var rejected=new java.util.concurrent.atomic.AtomicReference<Throwable>();
  Thread detached=new Thread(()->{try{catalog.requireSavedSourcesCurrent();}catch(Throwable failure){rejected.set(failure);}},"detached-source-authority");
  android.system.Os.beforeLstat=path->{if(Thread.currentThread()==detached&&path.equals(imported.toString())){reading.countDown();try{if(!resume.await(10,TimeUnit.SECONDS))throw new AssertionError("source overlap was not released");}catch(InterruptedException failure){throw new RuntimeException(failure);}}};
  try{
   detached.start();check(reading.await(10,TimeUnit.SECONDS),"detached authority never reached the original source-read boundary");
   Files.writeString(imported,new String(original,StandardCharsets.UTF_8).replace("Custom candidate","Changed custom candidate"));
   check(catalog.currentInventorySHA256().isEmpty(),"overlapping live source observer did not invalidate changed bytes");Files.write(imported,original);
   resume.countDown();detached.join(10000);check(!detached.isAlive(),"detached source read did not finish");
   check(rejected.get() instanceof IllegalStateException,"overlapping observed source change revived detached authority");
  }finally{Files.write(imported,original);resume.countDown();android.system.Os.beforeLstat=null;detached.join(10000);}
 }
 static void receipts(Path root)throws Exception{
  var f=fixture(root);var session=new AndroidNodeChainSession(f.profiles.currentOrderedPath());var catalog=new AndroidNodeCandidateCatalog(f.context,session,0);
  var nativeOwner=Libbox.routerNodeChainNewCandidateMeasurement(session.capture.plan,session.server,0,catalog.inventory,catalog);nativeOwner.prepare();JSONObject meta=new JSONObject(nativeOwner.metadata());String id=meta.getJSONArray("targets").getJSONObject(0).getString("id"),request="a".repeat(32);nativeOwner.start(request,id);String raw=nativeOwner.statusJSON();long now=System.currentTimeMillis();
  var accepted=AndroidNodeCandidateResult.capture(raw,request,meta,id,"Original",now);check(accepted.current(now)&&!accepted.current(accepted.expiresAt),"receipt read renewed120-second completion deadline");
  JSONObject responseMeta=new JSONObject(meta.toString()).put("measurement","routed-candidate-response");
  JSONObject response=new JSONObject(raw).put("measurement","routed-candidate-response");
  JSONObject privateRow=response.getJSONArray("results").getJSONObject(0);
  privateRow.put("kind","private-agent-response");privateRow.getJSONObject("benchmark").put("measurement","routed-candidate-response");
  check(AndroidNodeCandidateResult.capture(response.toString(),request,responseMeta,id,"Original",now).score>0,"qualified private candidate response missing");
  reject(()->AndroidNodeCandidateResult.capture(response.toString(),request,meta,id,"Original",now),"private response borrowed packet catalog");
  privateRow.put("kind","tcp-connect");reject(()->AndroidNodeCandidateResult.capture(response.toString(),request,responseMeta,id,"Original",now),"private response accepted a lazy handshake");

  for(String fault:List.of("capture","source","prefix","candidate","request","measurement","drain","expiry","samples","failed","nan","partial","alien-row","typed-samples","typed-complete","fractional-expiry")){
   JSONObject bad=new JSONObject(raw);JSONObject row=bad.getJSONArray("results").getJSONObject(0),b=row.getJSONObject("benchmark");
   switch(fault){case "capture":bad.put("capture_sha256","0".repeat(64));break;case "source":bad.put("candidate_source_sha256","0".repeat(64));break;case "prefix":bad.put("prefix_position",1);break;case "candidate":bad.put("candidate_id","other");break;case "request":bad.put("request_id","b".repeat(32));break;case "measurement":bad.put("measurement","routed-https");break;case "drain":bad.put("drained",false);break;case "expiry":bad.put("expires_at",bad.getLong("expires_at")+1);break;case "samples":b.getJSONObject("distribution").put("samples",49);break;case "failed":b.put("failed",1);break;case "nan":b.put("trimmed_mean_ms","NaN");break;case "partial":row.put("ready",false);break;case "alien-row":row.put("kind","private-node");break;case "typed-samples":b.getJSONObject("distribution").put("samples","50");break;case "typed-complete":bad.put("complete","true");break;case "fractional-expiry":bad.put("expires_at",bad.getLong("expires_at")+0.5);break;}
   reject(()->AndroidNodeCandidateResult.capture(bad.toString(),request,meta,id,"Original",now),"foreign/partial candidate receipt accepted: "+fault);
  }
 }
 static void reservationOwnership(Path root)throws Exception{
  var f=fixture(root);var session=new AndroidNodeChainSession(f.profiles.currentOrderedPath());var catalog=new AndroidNodeCandidateCatalog(f.context,session,0);
  var original=Libbox.routerNodeChainNewCandidateMeasurement(session.capture.plan,session.server,0,catalog.inventory,catalog);
  reject(()->Libbox.routerNodeChainNewCandidateMeasurement(session.capture.plan,session.server,0,catalog.inventory,catalog),"duplicate constructor acquired original reservation");
  check(!original.isClosed()&&RouterNodeChainCandidateMeasurement.last==original,"duplicate rejection retired the original reservation");
  original.prepare();original.close();
  var replacement=Libbox.routerNodeChainNewCandidateMeasurement(session.capture.plan,session.server,0,catalog.inventory,catalog);replacement.prepare();
  reject(original::close,"stale same-inventory handle accepted replacement cleanup");
  check(!replacement.isClosed(),"stale cleanup retired the replacement reservation");replacement.close();
 }
 static void lifetime(Path root,boolean factoryFailure)throws Exception{
  var f=fixture(root);new AndroidStandardExitStore(f.context).save(custom("2022-blake3-aes-256-gcm"));var session=new AndroidNodeChainSession(f.profiles.currentOrderedPath());var catalog=new AndroidNodeCandidateCatalog(f.context,session,0);
  RouterNodeChainCandidateMeasurement.factoryFailure=factoryFailure;RouterNodeChainCandidateMeasurement.holdClose=true;RouterNodeChainCandidateMeasurement.closeAttempts=0;
  CountDownLatch delivered=new CountDownLatch(1),finished=new CountDownLatch(1),observer=new CountDownLatch(1);java.util.concurrent.atomic.AtomicBoolean sorted=new java.util.concurrent.atomic.AtomicBoolean();
  var operation=AndroidNodeCandidateMeasurement.start(catalog,new AndroidNodeCandidateMeasurement.Callback(){public void changed(List<AndroidNodeCandidateResult> rows,String detail){if(detail.startsWith("Cancelling;")){observer.countDown();throw new IllegalStateException("disposed observer");}if(rows.size()==2){sorted.set(rows.get(0).id.startsWith("chain-")&&rows.get(0).score<rows.get(1).score);delivered.countDown();}}public void finished(Throwable failure){finished.countDown();}});
  if(!factoryFailure){check(delivered.await(10,TimeUnit.SECONDS),"actual host transaction never adopted a native completion");check(sorted.get(),"candidate display order did not use measured trimmed mean");}
  operation.cancel();long end=System.nanoTime()+TimeUnit.SECONDS.toNanos(10);while(RouterNodeChainCandidateMeasurement.closeAttempts==0&&System.nanoTime()<end)Thread.yield();
  check(RouterNodeChainCandidateMeasurement.closeAttempts>0&&AndroidMTUMeasurementGate.held()&&AndroidNodeCandidateMeasurement.busy(),"failed close released original MTU/worker ownership");
  reject(()->AndroidNodeCandidateMeasurement.start(catalog,null),"pending old cleanup allowed a replacement host");
  check(observer.await(10,TimeUnit.SECONDS),"cleanup did not notify original observer");RouterNodeChainCandidateMeasurement.holdClose=false;check(finished.await(10,TimeUnit.SECONDS),"original native cleanup did not finish");check(!AndroidMTUMeasurementGate.held()&&!AndroidNodeCandidateMeasurement.busy(),"joined cleanup retained a dead parent lease");RouterNodeChainCandidateMeasurement.factoryFailure=false;
 }
 static void borrowedLifetime(Path root,boolean factoryFailure)throws Exception{
  var f=fixture(root);new AndroidStandardExitStore(f.context).save(custom("2022-blake3-aes-256-gcm"));var session=new AndroidNodeChainSession(f.profiles.currentOrderedPath());var catalog=new AndroidNodeCandidateCatalog(f.context,session,0);
  Object lease=AndroidMTUMeasurementGate.acquire();
  reject(()->AndroidNodeCandidateMeasurement.startBorrowed(catalog,new Object(),null),"foreign outer lease entered a temporary candidate worker");
  RouterNodeChainCandidateMeasurement.factoryFailure=factoryFailure;RouterNodeChainCandidateMeasurement.holdClose=true;RouterNodeChainCandidateMeasurement.closeAttempts=0;
  CountDownLatch completed=new CountDownLatch(1),closing=new CountDownLatch(1),finished=new CountDownLatch(1);var callbackThread=new java.util.concurrent.atomic.AtomicReference<Thread>();var original=new java.util.concurrent.atomic.AtomicReference<AndroidNodeCandidateMeasurement>();
  var uncaught=new java.util.concurrent.ConcurrentLinkedQueue<Throwable>();Thread.UncaughtExceptionHandler previous=Thread.getDefaultUncaughtExceptionHandler();Thread.setDefaultUncaughtExceptionHandler((thread,error)->uncaught.add(error));
  try{
   var operation=AndroidNodeCandidateMeasurement.startBorrowed(catalog,lease,new AndroidNodeCandidateMeasurement.Callback(){
    public void changed(List<AndroidNodeCandidateResult> rows,String detail){if(detail.startsWith("Cancelling;"))closing.countDown();}
    public void completed(AndroidNodeCandidateMeasurement owner,List<AndroidNodeCandidateResult> rows)throws Exception{check(!owner.joined()&&rows.size()==2,"temporary completion lost the full original candidate inventory");for(var result:rows)owner.requireResult(result);completed.countDown();}
    public void finished(Throwable failure){callbackThread.set(Thread.currentThread());check(original.get().joined(),"completion observer ran before the native candidate join receipt");finished.countDown();throw new IllegalStateException("disposed temporary observer");}
   });original.set(operation);
   if(!factoryFailure)check(completed.await(10,TimeUnit.SECONDS),"temporary batch did not finish without waiting for a UI close");
   check(closing.await(10,TimeUnit.SECONDS),"temporary candidate cleanup did not retain a failed native join");
   check(!operation.joined()&&AndroidMTUMeasurementGate.owns(lease)&&AndroidNodeCandidateMeasurement.busy(),"borrowed candidate published join before native cleanup");
   reject(()->AndroidNodeCandidateMeasurement.startBorrowed(catalog,lease,null),"pending temporary native join allowed a second worker");
   RouterNodeChainCandidateMeasurement.holdClose=false;check(finished.await(10,TimeUnit.SECONDS),"temporary native cleanup did not finish");callbackThread.get().join(2000);
   check(!callbackThread.get().isAlive()&&uncaught.isEmpty(),"disposed completion observer escaped the retained cleanup worker");
   check(operation.joined()&&!AndroidNodeCandidateMeasurement.busy()&&AndroidMTUMeasurementGate.owns(lease),"borrowed candidate released the outer graph MTU lease");
   operation.cancel();check(AndroidMTUMeasurementGate.owns(lease),"retired inner worker released its preparation lease");
  }finally{Thread.setDefaultUncaughtExceptionHandler(previous);RouterNodeChainCandidateMeasurement.holdClose=false;RouterNodeChainCandidateMeasurement.factoryFailure=false;AndroidMTUMeasurementGate.release(lease);}
 }
 static void presentation(Path root)throws Exception{
  var f=fixture(root);new AndroidNodeChainSession(f.profiles.currentOrderedPath());
  var dialog=new AndroidNodeCandidateDialog(new android.app.Activity(f.context));dialog.show();
  var picker=android.app.AlertDialog.last;check(picker.items.length==1,"shipping picker offered lazy SS as a TCP timing prefix");picker.selected.run(picker,0);
  long end=System.nanoTime()+TimeUnit.SECONDS.toNanos(15);while(!android.widget.TextView.latest.contains("50/50")&&System.nanoTime()<end)Thread.yield();
  check(android.widget.TextView.latest.contains("50/50")&&android.widget.TextView.latest.contains("not HTTP, ICMP"),"shipping candidate readout did not label actual callback TCP scope");
  android.widget.Button.last.click.run(android.widget.Button.last);android.app.AlertDialog.last.selected.run(android.app.AlertDialog.last,0);
  end=System.nanoTime()+TimeUnit.SECONDS.toNanos(10);while((android.widget.EditText.last==null||android.app.AlertDialog.last.positive==null)&&System.nanoTime()<end)Thread.yield();
  check(android.widget.EditText.last!=null&&android.app.AlertDialog.last.positive!=null,"shipping candidate action did not show named path preview");android.widget.EditText.last.text="Measured UI future path";android.app.AlertDialog.last.positive.run(android.app.AlertDialog.last,0);
  end=System.nanoTime()+TimeUnit.SECONDS.toNanos(10);while(System.nanoTime()<end){try{if(Files.exists(f.rows)&&new JSONObject(Files.readString(f.rows)).getJSONArray("profiles").length()==1)break;}catch(org.json.JSONException partialFixtureWrite){}Thread.yield();}
  check(Files.exists(f.rows)&&f.profiles.list().get(0).name.equals("Measured UI future path"),"shipping Save callback did not append future profile");AndroidNodeChainSession.retained().requireCurrent();
  dialog.close();end=System.nanoTime()+TimeUnit.SECONDS.toNanos(10);while(AndroidNodeCandidateMeasurement.busy()&&System.nanoTime()<end)Thread.yield();
  check(!AndroidNodeCandidateMeasurement.busy()&&!AndroidMTUMeasurementGate.held()&&!android.app.AlertDialog.last.isShowing(),"Activity cleanup lost the original dialog or native lease");
 }
 static void adoption(Path root)throws Exception{
  for(String method:List.of("2022-blake3-aes-128-gcm","2022-blake3-aes-256-gcm","2022-blake3-chacha20-poly1305")){
   var f=new NodeChainCaptureHarness.Fixture(root,method.contains("aes-128")?"3/":method.contains("aes-256")?"4/mixed-awg":"8/mixed-awg");var entry=custom(method);new AndroidStandardExitStore(f.context).save(entry);
   var session=new AndroidNodeChainSession(f.profiles.currentOrderedPath());var catalog=new AndroidNodeCandidateCatalog(f.context,session,session.source.members.size()-3);
   CountDownLatch ready=new CountDownLatch(1),finished=new CountDownLatch(1);var measured=new java.util.concurrent.atomic.AtomicReference<List<AndroidNodeCandidateResult>>();
   var operation=AndroidNodeCandidateMeasurement.start(catalog,new AndroidNodeCandidateMeasurement.Callback(){public void changed(List<AndroidNodeCandidateResult> rows,String detail){if(rows.size()==2){measured.set(rows);ready.countDown();}}public void finished(Throwable failure){finished.countDown();}});
   check(ready.await(10,TimeUnit.SECONDS),"candidate adoption never received complete native results");
   AndroidVpnMutationGuard.busy=true;var before=new NodeChainCaptureHarness.State(f);
   var imported=measured.get().stream().filter(row->row.id.equals(entry.id)).findFirst().orElseThrow();var paired=measured.get().stream().filter(row->!row.id.equals(entry.id)).findFirst().orElseThrow();
   var proposal=new AndroidNodeCandidateProfile(operation,imported);check(proposal.description.contains(entry.id)&&proposal.description.contains(session.source.control.profileId),"proposal preview omitted custom candidate or original paired final");
   var saved=proposal.save(f.context,"Measured custom "+method);check(saved.mode.equals("shadowsocks"),"candidate profile saved runtime mode instead of actual final transport");
   byte[] beforeDuplicate=Files.readAllBytes(f.rows);
   reject(()->new AndroidNodeCandidateProfile(operation,paired),"paired final candidate truncated the retained suffix or duplicated its identity");
   check(Arrays.equals(beforeDuplicate,Files.readAllBytes(f.rows)),"incompatible next-hop proposal changed saved profiles");
   var after=new NodeChainCaptureHarness.State(f);for(Path path:before.files.keySet())if(!path.equals(f.rows))check(Arrays.equals(before.files.get(path),after.files.get(path)),"candidate save changed active original source");check(before.preferences.equals(after.preferences),"candidate save changed active builder preferences");session.requireCurrent();check(AndroidMTUMeasurementGate.held(),"candidate save retired original measurement lease");
   JSONArray records=new JSONObject(Files.readString(f.rows)).getJSONArray("profiles");check(records.length()==1,"candidate profile replaced another saved profile");
   JSONObject customRow=records.getJSONObject(0);JSONArray members=customRow.getJSONArray("multihop_nodes");
   check(members.length()==session.source.members.size(),"saved candidate path truncated its complete suffix");
   for(int position=0;position<members.length();position++){
    boolean replaced=position==catalog.prefix+1;JSONObject member=members.getJSONObject(position);
    check(member.getString("id").equals(replaced?entry.id:session.source.members.get(position).profileId),"Save replaced a position other than the measured next hop");
    check(member.getString("mode").equals(replaced?"shadowsocks":session.source.modes.get(position)),"Save changed a retained original mode");
   }
   check(customRow.getString("multihop_execution").equals(session.source.execution),"Save replaced the original requested execution");check(!customRow.toString().contains("api_token")&&!customRow.toString().contains("wg_private_key")&&!customRow.toString().contains(entry.secret),"future profile copied private credentials");
   reject(()->f.profiles.load(saved.id),"candidate profile loaded while connected");
   session.current=false;byte[] beforeStale=Files.readAllBytes(f.rows);reject(()->proposal.save(f.context,"Stale"),"retired candidate saved a future profile");check(Arrays.equals(beforeStale,Files.readAllBytes(f.rows)),"stale candidate wrote profile storage");
   operation.cancel();check(finished.await(10,TimeUnit.SECONDS),"candidate profile cleanup did not join");AndroidVpnMutationGuard.busy=false;
   f.profiles.load(saved.id);try(var compiled=AndroidNodeChainCapture.compile(f.profiles.currentOrderedPath())){check(new JSONObject(compiled.launchInput).getInt("schema")==2,"future imported profile did not compile after normal Load");}
  }
 }
 static void selectedResponse(Path root,String shape)throws Exception{
  for(int count:shape.equals("earlier-private")?List.of(5,9,16):List.of(3,4,9,16)){
   boolean use=shape.startsWith("use-"),drift=shape.equals("use-drift"),insert=shape.equals("insert-imported")||shape.equals("use-earlier")||drift;
   if ((shape.equals("use-private")||drift) && count!=4) continue;
   int lastPrefix=count-2, prefix=insert ? (count==4 ? 1:count==9 ? 3:12) : lastPrefix;
   if ((insert || shape.equals("all-imported")) && count==3) continue;
   int paired=insert || shape.equals("all-imported") || shape.equals("use-final") || count==3 ? -1 : shape.equals("earlier-private") ? 2 : lastPrefix;
   var originals=new JSONObject(Files.readString(Path.of(System.getenv("ROUTERVPN_ANDROID_CHAIN_FIXTURE"))));
   JSONArray members=originals.getJSONArray("3/");
   if(count==16){
    JSONObject wg=members.getJSONObject(0).getJSONObject("profiles").getJSONObject("wg");
    for(String name:List.of("wg.conf","wg-socks.conf"))if(wg.has(name)){
     String original=new String(Base64.getDecoder().decode(wg.getString(name)),StandardCharsets.UTF_8);
     wg.put(name,Base64.getEncoder().encodeToString(original.replace("MTU = 2000","MTU = 4096").getBytes(StandardCharsets.UTF_8)));
    }
   }
   // The two-node final has its own SS2022 source for this same paired identity.
   if(count>3)members.getJSONObject(1).getJSONObject("profiles").put("shadowsocks",originals.getJSONArray("2/").getJSONObject(1).getJSONObject("profiles").getJSONObject("shadowsocks"));
   var f=new NodeChainCaptureHarness.Fixture(root,members);var middle=custom("2022-blake3-aes-256-gcm");
   new AndroidStandardExitStore(f.context).save(middle);
   JSONArray extra=originals.getJSONArray("8/mixed-awg");
   var alternate=f.nodes.importBundle(extra.getJSONObject(7).toString().getBytes(StandardCharsets.UTF_8));
   String recursiveID="";
   if (use&&count==3) {
    var second=originals.getJSONArray("7/mixed-awg").getJSONObject(6);
    var linked=f.nodes.importBundle(second.toString().getBytes(StandardCharsets.UTF_8));
    recursiveID=f.nodes.candidateSource(linked.id).profileId;
   }
   var additional=new java.util.HashMap<Integer,String>();
   for(int i=2;i<=lastPrefix;i++){
    if(i==paired)continue;
    var node=custom("2022-blake3-aes-256-gcm");node.id=String.format("%032x",i);node.server="198.51.100."+(76+i);
    node.expectedPublicIp="203.0.113."+(76+i);byte[] key=new byte[32];Arrays.fill(key,(byte)i);node.secret=Base64.getEncoder().encodeToString(key);
    new AndroidStandardExitStore(f.context).save(node);additional.put(i,node.id);
   }
   f.nodes.select(f.control().id);
   var draft=new AndroidOrderedPathSelection(f.nodes,f.profiles);
   String privateID=draft.members().get(1).source.id;
   draft.removePrefix(1);draft.setPrefixMode(0,"wg");draft.addPrefix(middle.id,"shadowsocks");draft.setExecution("auto");
   for(int i=2;i<=lastPrefix;i++)draft.addPrefix(i==paired?privateID:additional.get(i),"shadowsocks");
   var staged=draft.candidateDraftCapture(prefix).call();
   check(staged.selectedCandidateDraft()&&staged.members.size()==count,"complete private candidate draft lost its suffix");
   if (!use) draft.save();
   var source=use ? staged : f.profiles.currentOrderedPath();
   var capture=use ? new AndroidNodeChainSession(source,new Object()) : new AndroidNodeChainSession(source);
   check(AndroidNodeChainCapture.responsePrefix(source.members,source.modes,prefix,"auto")&&capture.capture.ownsSelectedCandidatePrefix(source,prefix),"Compare import lacked original measurable capture");
   var crossedModes=new ArrayList<>(source.modes);crossedModes.set(0,"awg2-fast");
   check(!AndroidNodeChainCapture.responsePrefix(source.members,source.modes,prefix,"server")&&!AndroidNodeChainCapture.responsePrefix(source.members,crossedModes,prefix,"auto"),"Server or AWG acquired private response");
   for(int i=1;i<lastPrefix;i++)check(AndroidNodeChainCapture.responsePrefix(source.members,source.modes,i,"auto"),"an earlier import gained the wrong response scope");
   var potential=AndroidNodeCandidateCatalog.captureSources(f.context,source,prefix);
   var alternateSource=f.nodes.candidateSource(alternate.id);
   check(potential.rows.stream().anyMatch(r->r.id.equals(alternateSource.profileId)&&!r.input.isEmpty())&&
         potential.rows.stream().noneMatch(r->source.members.stream().anyMatch(m->m.profileId.equals(r.id))),"distinct Compare response catalog retained original final or omitted real alternative");
   capture.execution=capture.capture.multipleImported?Libbox.routerNodeChainMultipleImportedExecutionFromLaunch(capture.capture.launchInput,"auto"):Libbox.routerNodeChainExecutionFromLaunch(capture.capture.launchInput,"auto");
   capture.execution.testSource=capture.capture.plan;
   capture.execution.testWinner="server";
   reject(()->new AndroidNodeCandidateCatalog(f.context,capture,prefix),"actual Server winner acquired selected Local response authority");
   capture.execution.testWinner="local";
   var catalog=new AndroidNodeCandidateCatalog(f.context,capture,prefix);
   check(catalog.selectedPrefixID().equals(source.members.get(prefix).profileId)&&catalog.measurement.equals("routed-candidate-response"),"Local winner lost measured import identity");
   var before=new NodeChainCaptureHarness.State(f);
   var published=new CountDownLatch(1);var finished=new CountDownLatch(1);var scored=new java.util.concurrent.atomic.AtomicReference<AndroidNodeCandidateResult>();
   var operation=AndroidNodeCandidateMeasurement.start(catalog,new AndroidNodeCandidateMeasurement.Callback(){
    public void changed(List<AndroidNodeCandidateResult> rows,String detail){for(var row:rows)if(row.id.equals(alternateSource.profileId)){scored.set(row);published.countDown();}}
    public void finished(Throwable error){finished.countDown();}
   });
   try {
    check(published.await(8,TimeUnit.SECONDS),"no original Compare Local response score survived the selected receipt checks");
    var proposal=new AndroidNodeCandidateProfile(operation,scored.get());
    if (use) {
     var scoredRow=scored.get();
     var changeAfterObservation=new java.util.concurrent.atomic.AtomicBoolean();
     AndroidNodeCandidateProfile.SavedResultAuthority authority=row->{
      if (!operation.joined() || row!=scoredRow) throw new IllegalStateException("original measurement has not joined");
      source.requireCurrent();catalog.requireSavedSourcesCurrent();
      if (changeAfterObservation.compareAndSet(true,false)) {
       var suffix=source.members.get(prefix+1).external();suffix.server="198.51.100.230";
       new AndroidStandardExitStore(f.context).save(suffix);
      }
     };
     var named=AndroidNodeCandidateProfile.captureTemporary(operation,scoredRow,authority);
     var insertion=AndroidNodeCandidateProfile.captureDraftInsertion(operation,scoredRow,authority,named);
     reject(()->insertion.useInDraft(draft),"unjoined measurement changed the draft");
     operation.cancel();check(finished.await(10,TimeUnit.SECONDS),"original insertion measurement did not join");
     if (drift) {
      changeAfterObservation.set(true);
      reject(()->insertion.useInDraft(draft),"a changed suffix endpoint entered the completed draft");
      check(draft.members().size()==count&&draft.members().get(count-1).source.id.equals(source.control.id)
        &&before.preferences.equals(new NodeChainCaptureHarness.State(f).preferences)&&!Files.exists(f.rows),"source refusal changed the draft, Home, or saved profiles");
      continue;
     }
     var other=new AndroidOrderedPathSelection(f.nodes,f.profiles);
     other.removePrefix(1);other.setPrefixMode(0,"wg");other.addPrefix(middle.id,"shadowsocks");other.setExecution("auto");
     for(int i=2;i<=lastPrefix;i++)other.addPrefix(i==paired?privateID:additional.get(i),"shadowsocks");
     var copy=other.candidateDraftCapture(prefix).call();
     check(copy.modes.equals(source.modes)&&copy.members.size()==source.members.size(),"foreign editor did not reproduce the original selection");
     reject(()->insertion.useInDraft(other),"a different editor adopted the measured result");
     var expected=new ArrayList<String>();for(var member:source.members)expected.add(member.id);
     expected.add(prefix+1,alternate.id);
     insertion.useInDraft(draft);
     var actual=new ArrayList<String>();for(var member:draft.members())actual.add(member.source.id);
     check(actual.equals(expected)&&draft.members().get(prefix+1).mode.equals("shadowsocks"),"draft insertion lost an original suffix or final node");
     before.same(f,"explicit Use in draft");
     reject(()->insertion.useInDraft(draft),"the previous receipt updated the revised draft a second time");
     int next=actual.size()-2;var recaptured=draft.candidateDraftCapture(next).call();
     check(recaptured!=source&&recaptured.members.size()==count+1&&draft.canMeasureResponseThrough(next),"the revised draft did not require a fresh complete source");
     var fresh=new AndroidNodeChainSession(recaptured,new Object());
     try(var compiled=fresh.capture){
      check(compiled.ownsSelectedCandidatePrefix(recaptured,next),"newly inserted private source failed to reopen at its own position");
      if (count==3) {
       fresh.execution=Libbox.routerNodeChainMultipleImportedExecutionFromLaunch(compiled.launchInput,"auto");
       fresh.execution.testSource=compiled.plan;fresh.execution.testWinner="local";
       var live=new AndroidNodeCandidateCatalog(f.context,fresh,next);
       var observed=new CountDownLatch(1);var joined=new CountDownLatch(1);String wanted=recursiveID;
       var repeat=AndroidNodeCandidateMeasurement.start(live,new AndroidNodeCandidateMeasurement.Callback(){
        public void changed(List<AndroidNodeCandidateResult> rows,String detail){if(rows.stream().anyMatch(row->row.id.equals(wanted)))observed.countDown();}
        public void finished(Throwable error){joined.countDown();}
       });
       try {check(observed.await(10,TimeUnit.SECONDS)&&live.selectedPrefixID().equals(alternateSource.profileId),"fresh Compare trial did not measure after the inserted draft hop");}
       finally {repeat.cancel();check(joined.await(10,TimeUnit.SECONDS),"repeat candidate trial did not join");}
       before.same(f,"recursive comparison in the unsaved draft");
      }
     }
     continue;
    }
    var saved=proposal.save(f.context,"Compare private response final");
    var after=new NodeChainCaptureHarness.State(f);check(before.preferences.equals(after.preferences),"future selected final changed Home settings");
    for(Path path:before.files.keySet())if(!path.equals(f.rows))check(Arrays.equals(before.files.get(path),after.files.get(path)),"future selected final changed original source");
    check(capture.candidateExecutionOwner()==catalog.executionOwner&&"local".equals(catalog.executionOwner.execution()),"future profile reselected or retired the original execution");
    operation.cancel();check(finished.await(10,TimeUnit.SECONDS),"selected response callbacks did not drain");
    f.profiles.load(saved.id);var loaded=f.profiles.currentOrderedPath();
    var expectedModes=new ArrayList<>(source.modes);
    if(insert)expectedModes.add(prefix+1,"shadowsocks");
    check(loaded.execution.equals("auto")&&loaded.modes.equals(expectedModes)&&loaded.members.get(prefix+1).id.equals(alternate.id),"named profile Load changed the measured successor or requested Compare");
    for(int i=0;i<count;i++){
     if(!insert&&i==count-1)continue;
     var member=loaded.members.get(insert&&i>prefix ? i+1:i);
     check(member.id.equals(source.members.get(i).id)&&member.proofId.equals(source.members.get(i).proofId),"named Load substituted an original prefix, suffix or final identity");
    }
    try(var reopened=AndroidNodeChainCapture.compile(loaded)){check(reopened.plan!=null,"reloaded selected response did not compile");}
   } finally {operation.cancel();finished.await(10,TimeUnit.SECONDS);}
  }
 }
 public static void main(String[] args)throws Exception{try{Path root=Path.of(args[0]);if(args.length==2&&List.of("selected-response","all-imported","earlier-private","insert-imported","use-earlier","use-final","use-private","use-drift").contains(args[1])){selectedResponse(root,args[1]);System.out.println("Android selected Compare private response: "+checks+" original store/Go compiler/selected callback checks PASS");return;}if(args.length==2&&args[1].equals("capacity")){largeCatalog(root);System.out.println("Android complete candidate inventory: "+checks+" original store, Go metadata and receipt checks PASS");return;}openVPNTCPCandidates(root);capturedSources(root);sources(root);overlappingSavedSources(root);receipts(root);reservationOwnership(root);lifetime(root,false);lifetime(root,true);borrowedLifetime(root,false);borrowedLifetime(root,true);adoption(root);presentation(root);System.out.println("Android retained-prefix candidates: "+checks+" shipping source, receipt and drain checks PASS");}finally{AndroidVpnMutationGuard.busy=false;RouterNodeChainCandidateMeasurement.holdClose=false;AndroidNodeCandidateMeasurement.cancelActive();}}
}'''


def prepare(src, app, java):
    ORIGINAL_PREPARE(src, app, java)
    for name in ('AndroidNodeCandidateCatalog','AndroidNodeCandidateResult','AndroidNodeCandidateMetadata','AndroidNodeCandidateMeasurement','AndroidNodeCandidateDialog','AndroidNodeCandidateProfile','AndroidMTUMeasurementGate'):
        shutil.copyfile(java/(name+'.java'),app/(name+'.java'))
    ui = {
        'android/system/StructStat.java': 'package android.system;public final class StructStat{public long st_dev,st_ino;}',
        'android/system/Os.java': 'package android.system;public final class Os{public static volatile java.util.function.Consumer<String> beforeLstat;public static StructStat lstat(String path)throws Exception{var hook=beforeLstat;if(hook!=null)hook.accept(path);try{java.util.Map<String,Object> a=java.nio.file.Files.readAttributes(java.nio.file.Path.of(path),"unix:dev,ino",java.nio.file.LinkOption.NOFOLLOW_LINKS);StructStat s=new StructStat();s.st_dev=((Number)a.get("dev")).longValue();s.st_ino=((Number)a.get("ino")).longValue();return s;}catch(java.nio.file.NoSuchFileException missing){throw new ErrnoException("lstat",OsConstants.ENOENT);}}}',
        'android/system/ErrnoException.java': 'package android.system;public final class ErrnoException extends Exception{public final int errno;public ErrnoException(String operation,int errno){super(operation);this.errno=errno;}}',
        'android/system/OsConstants.java': 'package android.system;public final class OsConstants{public static final int ENOENT=2;}',
        'android/app/Activity.java': 'package android.app;public class Activity extends android.content.Context{final android.content.Context original;public Activity(android.content.Context original){super(original.getFilesDir());this.original=original;}public android.content.Context getApplicationContext(){return original;}public android.content.MemoryPreferences getSharedPreferences(String key,int mode){return original.getSharedPreferences(key,mode);}public boolean isFinishing(){return false;}public boolean isDestroyed(){return false;}public void runOnUiThread(Runnable action){action.run();}}',
        'android/app/AlertDialog.java': 'package android.app;public class AlertDialog{public interface Click{void run(AlertDialog d,int which);}public interface Dismiss{void run(AlertDialog d);}public static volatile AlertDialog last;public CharSequence[] items;public Click selected,negative,positive;boolean showing;Dismiss dismissed;public boolean isShowing(){return showing;}public void show(){showing=true;last=this;}public void dismiss(){showing=false;if(dismissed!=null)dismissed.run(this);}public void setOnDismissListener(Dismiss callback){dismissed=callback;}public static class Builder{final AlertDialog dialog=new AlertDialog();public Builder(Activity a){}public Builder setTitle(String text){return this;}public Builder setMessage(String text){return this;}public Builder setItems(CharSequence[] items,Click callback){dialog.items=items;dialog.selected=callback;return this;}public Builder setNegativeButton(String text,Click callback){dialog.negative=callback;return this;}public Builder setPositiveButton(String text,Click callback){dialog.positive=callback;return this;}public Builder setView(Object view){return this;}public AlertDialog create(){return dialog;}public AlertDialog show(){dialog.show();return dialog;}}}',
        'android/widget/TextView.java': 'package android.widget;public class TextView{public static volatile String latest="";public TextView(android.content.Context c){}public void setPadding(int a,int b,int c,int d){}public void setTextIsSelectable(boolean value){}public void setText(String text){latest=text;}}',
        'android/widget/LinearLayout.java': 'package android.widget;public class LinearLayout{public static final int VERTICAL=1;public LinearLayout(android.content.Context c){}public void setOrientation(int value){}public void addView(Object view){}}',
        'android/widget/Button.java': 'package android.widget;public class Button{public interface Click{void run(Button b);}public static volatile Button last;public Click click;public Button(android.content.Context c){last=this;}public void setText(String value){}public void setOnClickListener(Click value){click=value;}}',
        'android/widget/EditText.java': 'package android.widget;public class EditText{public static volatile EditText last;public String text="";public EditText(android.content.Context c){last=this;}public void setHint(String value){}public CharSequence getText(){return text;}}',
        'android/widget/ScrollView.java': 'package android.widget;public class ScrollView{public ScrollView(android.content.Context c){}public void addView(Object view){}}',
    }
    for name,body in ui.items():
        target=src/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_text(body)
    (app/'AndroidNodeChainSession.java').write_text(SESSION)
    (app/'AndroidNodeCandidatePrefixCapture.java').write_text('''package com.eabusham.routervpn;final class AndroidNodeCandidatePrefixCapture{final String sourceSHA256="",configSHA256="";final io.nekohasekai.libbox.RouterNodeChainCandidatePreparation plan=null;void close()throws Exception{throw new IllegalStateException("No idle prefix in connected candidate fixture");}}''')
    (app/'NodeCandidateHarness.java').write_text(HARNESS)
    native=src/'io/nekohasekai/libbox'
    (native/'CommandServer.java').write_text('package io.nekohasekai.libbox;public class CommandServer{}')
    (native/'RouterNodeChainCandidateCatalog.java').write_text('package io.nekohasekai.libbox;public interface RouterNodeChainCandidateCatalog{String currentInventorySHA256();}')
    (native/'RouterNodeChainCandidateMeasurement.java').write_text(framed_native())
    (native/'RouterNodeChainCandidatePreparation.java').write_text('''package io.nekohasekai.libbox;public class RouterNodeChainCandidatePreparation{public String metadataPage(int offset){return "";}public String metadata(){throw new IllegalStateException("No idle prefix in connected candidate fixture");}public String captureSHA256(){return "";}public String statusJSON(){return "{}";}public void start(String request,String id)throws Exception{throw new IllegalStateException("No idle prefix in connected candidate fixture");}public void cancel(String request){}public void drain(String request)throws Exception{throw new IllegalStateException("No idle prefix in connected candidate fixture");}public void close()throws Exception{throw new IllegalStateException("No idle prefix in connected candidate fixture");}}''')
    p=native/'Libbox.java';s=p.read_text();s=s[:-1]+r'''
public static boolean qualifiedSelectedResponse(RouterNodeChainExecution selected,int position)throws Exception{return "true".equals(call("selected-response-position",selected.source(),Integer.toString(position)));}
public static String routerNodeChainCandidatePrefixMeasurement(RouterNodeChain p,int position)throws Exception{return call("candidate-metric",p.launchInput(),Integer.toString(position));}
public static String routerNodeChainCandidatePrefixProof(RouterNodeChain p,int position)throws Exception{return call("candidate-proof",p.launchInput(),Integer.toString(position));}
public static boolean routerNodeChainCandidateInputSupportedForMeasurement(String input,String metric)throws Exception{return "true".equals(call("candidate-supported-metric",input,metric));}
public static boolean routerNodeChainCandidateInputSupported(String input)throws Exception{return "true".equals(call("candidate-supported",input));}
public static RouterNodeChainCandidateMeasurement routerNodeChainNewCandidateMeasurement(RouterNodeChain plan,CommandServer server,int position,String inventory,RouterNodeChainCandidateCatalog catalog)throws Exception{return new RouterNodeChainCandidateMeasurement(plan,position,inventory,catalog);}
}''';p.write_text(s)
    install_unavailable(src)
    # Execution is an explicit winner/epoch double here. The source, catalog,
    # full candidate inputs, Java receipt/adoption and named profile Load are real.
    execution=native/'RouterNodeChainExecution.java'
    text=execution.read_text()
    original='public String execution(){throw new IllegalStateException("No native execution proof");}'
    assert text.count(original)==1
    execution.write_text(text.replace(original,'public RouterNodeChain testSource;public String testWinner="";public String execution(){if(testWinner.isEmpty())throw new IllegalStateException("No fixture selected winner");return testWinner;}'))
    typed=native/'RouterNodeChainExecutionCandidateMeasurement.java'
    typed.write_text('''package io.nekohasekai.libbox;
import org.json.*;
public final class RouterNodeChainExecutionCandidateMeasurement {
 private final RouterNodeChainExecution selected;private final RouterNodeChainCandidateMeasurement service;
 RouterNodeChainExecutionCandidateMeasurement(RouterNodeChainExecution selected,RouterNodeChain source,int position,String inventory,RouterNodeChainCandidateCatalog catalog)throws Exception{
  if(!"local".equals(selected.execution())||!"auto".equals(selected.requestedExecution())||!Libbox.qualifiedSelectedResponse(selected,position))throw new IllegalStateException("No captured Local response trial");
  this.selected=selected;service=new RouterNodeChainCandidateMeasurement(source,position,inventory,catalog);
 }
 public void prepare()throws Exception{service.prepare();}
 public String metadata()throws Exception{return new JSONObject(service.metadata()).put("preparation_source_sha256",selected.sourceSHA256()).put("preparation_config_sha256",selected.configSHA256()).put("requested_execution","auto").put("execution",selected.execution()).put("selection_epoch",17).toString();}
 public String metadataPage(int offset){throw new AssertionError("Unexpected paged inventory in selected response fixture");}
 public String captureSHA256()throws Exception{return service.captureSHA256();}
 public void start(String r,String id)throws Exception{service.start(r,id);}
 public void cancel(String r){service.cancel(r);}public void drain(String r)throws Exception{service.drain(r);}
 public String statusJSON()throws Exception{return service.statusJSON();}public void close()throws Exception{service.close();}
}''')
    marker='throw new IllegalStateException("No typed connected candidate runtime in this ordinary fixture");'
    lib=native/'Libbox.java';text=lib.read_text()
    start=text.index('public static RouterNodeChainExecutionCandidateMeasurement routerNodeChainExecutionNewCandidateMeasurement')
    lib.write_text(text[:start]+text[start:].replace(marker,'return new RouterNodeChainExecutionCandidateMeasurement(owner,owner.testSource,prefix,inventory,(RouterNodeChainCandidateCatalog)catalog);',1))


def generate_fixture(root, work, env):
    generator=work/'android_candidate_fixture_test.go';generator.write_text(chain.GENERATOR.replace('nodes:=nodeChainModeFixtureNodes(t,modes,layers)', r'''nodes:=nodeChainModeFixtureNodes(t,modes,layers)
  for position,node:=range nodes{if node.mode=="shadowsocks"{var assets map[string]string;_ = json.Unmarshal([]byte(node.inputs.Files),&assets);graph:=externalTestRead(t,string(mustDecodeChainAsset(t,assets["sing-box.json"])));out:=graph["outbounds"].([]any)[0].(map[string]any);out["method"]="2022-blake3-aes-256-gcm";assets["sing-box.json"]=base64.StdEncoding.EncodeToString([]byte(startJSON(t,graph)));var err error;nodes[position],err=NewNodeProfile(node.mode,startJSON(t,assets),node.inputs.ProfileJSON,node.inputs.Start,"");if err!=nil{t.Fatal(err)}}}'''))
    overlay=work/'candidate-overlay.json';overlay.write_text(json.dumps({'Replace':{str(root/'internal/mobilemultihop/android_candidate_fixture_test.go'):str(generator)}}))
    env=dict(env,ROUTERVPN_ANDROID_CHAIN_FIXTURE=str(work/'candidate-originals.json'))
    subprocess.run(['go','test','-count=1','-overlay='+str(overlay),'./internal/mobilemultihop','-run','^TestAndroidOrderedSourceFixture$'],cwd=root,env=env,check=True,timeout=180)
    return env


def run(root, work, app, classes, jar, env, imported_only=False):
    env = generate_fixture(root, work, env)
    data=work/'candidate-data';data.mkdir()
    subprocess.run(['java','-cp',str(classes)+os.pathsep+str(jar),'com.eabusham.routervpn.NodeCandidateHarness',str(data)],env=env,check=True,timeout=120)
    response=work/'selected-response';response.mkdir()
    subprocess.run(['java','-cp',str(classes)+os.pathsep+str(jar),'com.eabusham.routervpn.NodeCandidateHarness',str(response),'selected-response'],env=env,check=True,timeout=120)
    for shape in ('all-imported','earlier-private','insert-imported','use-earlier','use-final','use-private','use-drift'):
        target=work/shape;target.mkdir()
        subprocess.run(['java','-cp',str(classes)+os.pathsep+str(jar),'com.eabusham.routervpn.NodeCandidateHarness',str(target),shape],env=env,check=True,timeout=120)
    for name, before, after, witness in (
        ('AndroidNodeStore', 'if (draftCatalog != catalog || draftCatalog == null)', 'if (draftCatalog == null)', 'a different editor adopted the measured result'),
        ('AndroidNodeCandidateProfile', 'requireSavedCurrent();\n            draft.insertMeasured', 'draft.insertMeasured', 'unjoined measurement changed the draft'),
    ):
        target=work/('draft-control-'+name);target.mkdir()
        code=(JAVA/(name+'.java')).read_text();assert code.count(before)==1
        changed=target/(name+'.java');changed.write_text(code.replace(before,after))
        cp=os.pathsep.join(map(str,[target,classes,jar]))
        subprocess.run(['javac','--release','17','-cp',cp,'-d',str(target),str(changed)],check=True,timeout=60)
        data=target/'data';data.mkdir()
        failed=subprocess.run(['java','-cp',cp,'com.eabusham.routervpn.NodeCandidateHarness',str(data),'use-final'],env=env,capture_output=True,text=True,timeout=120)
        assert failed.returncode!=0 and witness in failed.stderr,failed.stdout+failed.stderr
        print('Android draft insertion causal control rejected:',witness,flush=True)
    original=(JAVA/'AndroidNodeCandidateMeasurement.java').read_text()
    old='int expectedFields = "routed-candidate-response".equals(catalog.measurement) ? 13 : 12;'
    assert original.count(old)==1
    changed=work/'packet-only-receipt';changed.mkdir()
    mutant=changed/'AndroidNodeCandidateMeasurement.java';mutant.write_text(original.replace(old,'int expectedFields = 12;'))
    cp=os.pathsep.join(map(str,[changed,classes,jar]))
    subprocess.run(['javac','--release','17','-cp',cp,'-d',str(changed),str(mutant)],check=True,timeout=60)
    failed=subprocess.run(['java','-cp',cp,'com.eabusham.routervpn.NodeCandidateHarness',str(response),'selected-response'],env=env,capture_output=True,text=True,timeout=120)
    assert failed.returncode!=0 and 'no original Compare Local response score survived the selected receipt checks' in failed.stderr,failed.stdout+failed.stderr
    capacity=work/'candidate-capacity';capacity.mkdir()
    subprocess.run(['java','-cp',str(classes)+os.pathsep+str(jar),'com.eabusham.routervpn.NodeCandidateHarness',str(capacity),'capacity'],env=env,check=True,timeout=120)
    controls = (
        ('AndroidNodeCandidateCatalog', 'original.source!=originalSource', 'false', 'same-byte foreign source bound captured catalog'),
        ('AndroidNodeCandidateCatalog', 'catch(Exception changed){savedSourcesInvalidated=true;throw changed;}', 'catch(Exception changed){throw changed;}', 'prepermission source change-away/back revived catalog'),
        ('AndroidNodeCandidateProfile', 'private void requireCurrent()throws Exception {operation.requireResult(result);}', 'private void requireCurrent()throws Exception {}', 'retired candidate saved a future profile'),
        ('AndroidNodeCandidateCatalog', '||!signature.equals(currentSignature())', '||false', 'unsupported candidate source replacement accepted'),
        ('AndroidNodeCandidateCatalog', '+before.st_dev+":"+before.st_ino+":"', '+""', 'same-byte replacement revived original file identity'),
        ('AndroidNodeCandidateCatalog', 'return before.st_dev + ":" + before.st_ino + ":" + AndroidTorProfile.digest(bytes);', 'return AndroidTorProfile.digest(bytes);', 'same-byte imported container replacement revived original identity'),
        ('AndroidNodeCandidateMeasurement', 'catch(Throwable observerFailure){ /* An observer cannot abandon retained native cleanup. */ }', 'catch(Throwable observerFailure){ throw observerFailure; }', 'original native cleanup did not finish'),
        ('AndroidNodeCandidateResult', 'integer(benchmark,"failed")!=0', 'false', 'foreign/partial candidate receipt accepted: failed'),
        ('AndroidNodeCandidateResult', 'expires-measured!=120000', 'false', 'foreign/partial candidate receipt accepted: expiry'),
        ('AndroidNodeCandidateMeasurement', 'boolean joined=false;', 'AndroidMTUMeasurementGate.release(lease);boolean joined=false;', 'failed close released original MTU/worker ownership'),
        ('AndroidNodeCandidateMeasurement', 'if(!borrowedLease)AndroidMTUMeasurementGate.release(lease);', 'AndroidMTUMeasurementGate.release(lease);', 'borrowed candidate released the outer graph MTU lease'),
        ('AndroidNodeCandidateMeasurement', 'boolean joined=false;', 'this.joined.countDown();boolean joined=false;', 'borrowed candidate published join before native cleanup'),
        ('AndroidNodeCandidateMeasurement', 'try{callback.finished(failure);}catch(Throwable ignored){}', 'callback.finished(failure);', 'disposed completion observer escaped the retained cleanup worker'),
        ('AndroidNodeCandidateCatalog', 'if(signature!=null&&!signature.equals(current))savedSourcesInvalidated=true;', '', 'observed source change-away/back revived post-DOWN catalog authority'),
        ('AndroidNodeCandidateCatalog', 'if(savedSourcesInvalidated||!signature.equals(observed))', 'if(!signature.equals(observed))', 'overlapping observed source change revived detached authority'),
    )
    for index,(name,old,new,witness) in enumerate(controls):
        original=(app/(name+'.java')).read_text();assert original.count(old)==1,old
        source=work/('candidate-mutant-'+str(index));source.mkdir();mutation=source/(name+'.java');mutation.write_text(original.replace(old,new))
        target=source/'classes';shutil.copytree(classes,target);classpath=str(target)+os.pathsep+str(jar)
        subprocess.run(['javac','--release','17','-cp',classpath,'-d',str(target),str(mutation)],check=True,timeout=60)
        private=source/'private';private.mkdir()
        failed=subprocess.run(['java','-cp',classpath,'com.eabusham.routervpn.NodeCandidateHarness',str(private)],env=env,capture_output=True,text=True,timeout=120)
        assert failed.returncode!=0 and witness in failed.stderr,failed.stdout+failed.stderr
        print('Android candidate causal control rejected:',name,witness,flush=True)



if __name__=='__main__':
    chain.prepare_sources=prepare;chain.compiler_source=compiler;chain.run=run
    sys.argv=[sys.argv[0],'--case-family','ordered-chain'];profiles.main()
