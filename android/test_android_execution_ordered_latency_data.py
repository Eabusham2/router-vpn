#!/usr/bin/env python3
"""Exercise the actual Android execution-fifty metadata and history classes.

The small Go helper uses the shipping private-JSON validator and the actual
hopmeasure receipt/status structs. Its metadata values are fixtures, not fifty
network exchanges. The execution capture's actual anonymous Go struct fields
are projected unchanged. Android Context and atomic-file operations have
explicit filesystem fault boundaries; this does not prove Android syscalls,
native owner adoption, SDK integration, or a device tunnel.
"""
from pathlib import Path
import hashlib
import json
import os
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
JAVA = ROOT/'android/app/src/main/java/com/eabusham/routervpn'
APP = 'com/eabusham/routervpn/'
NATIVE = 'io/nekohasekai/libbox/'
NAMES = ('AndroidOrderedExecutionLatencyCapture', 'AndroidOrderedExecutionLatencyStore', 'AndroidOrderedLatencyStore')
FAMILIES = ('matrix', 'capture-refusals', 'receipt-refusals', 'ordinary-boundary', 'history', 'rollback', 'bounds')
PHASES = []


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def identity(path):
    path = Path(path)
    before = path.stat(); digest = sha(path); after = path.stat()
    fields = lambda value: (value.st_dev, value.st_ino, value.st_size, value.st_mode, value.st_mtime_ns, value.st_ctime_ns)
    if fields(before) != fields(after) or not stat.S_ISREG(before.st_mode):
        raise AssertionError('test input/tool changed while hashing')
    return dict(path=str(path), resolved=str(path.resolve()), sha256=digest, fields=fields(before))


def sources():
    paths = {Path(__file__), ROOT/'go.mod', ROOT/'cmd/router-agent/main.go', JAVA/'AndroidTorProfile.java', JAVA/'AndroidPrivateFileStore.java'}
    if os.path.lexists(ROOT/'go.sum'):
        paths.add(ROOT/'go.sum')
    paths.update(JAVA/(name+'.java') for name in NAMES)
    for path in (ROOT/'internal').rglob('*.go'):
        paths.add(path)
    if any(path.is_symlink() or not path.is_file() for path in paths):
        raise AssertionError('the complete source must contain original regular inputs')
    return {str(path.relative_to(ROOT)): sha(path) for path in sorted(paths)}


def execute(command, bound, *, cwd=ROOT, env=None, expected=0):
    child = subprocess.Popen([str(value) for value in command], cwd=cwd, env=env,
                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, start_new_session=True)
    timed_out = False
    try:
        output, _ = child.communicate(timeout=bound)
    except subprocess.TimeoutExpired:
        timed_out = True; os.killpg(child.pid, signal.SIGTERM)
        try: output, _ = child.communicate(timeout=2)
        except subprocess.TimeoutExpired:
            os.killpg(child.pid, signal.SIGKILL); output, _ = child.communicate(timeout=5)
    try: os.killpg(child.pid, 0); joined = False
    except ProcessLookupError: joined = True
    if not joined: os.killpg(child.pid, signal.SIGKILL)
    PHASES.append(dict(command=[str(value) for value in command], bound_seconds=bound,
                       returncode=child.returncode, timed_out=timed_out, process_group_joined=joined,
                       output_sha256=hashlib.sha256(output.encode()).hexdigest()))
    if timed_out or not joined or child.returncode != expected:
        # This helper and harness emit fixture names/metadata only; no imported
        # profile or production private bundle is read by this gate.
        print(output[-16000:], file=sys.stderr)
        raise AssertionError('the original execution-data fixture failed or did not join')
    return output


def go_source():
    native = (ROOT/'internal/mobilemultihop/node_chain_execution_latency.go').read_text()
    hop = re.search(r'type nodeChainExecutionLatencyHop struct \{.*?\n\}', native, re.S)
    capture = re.search(r'capture, err := json.Marshal\((struct \{.*?\n\t\})\{1, p.SourceSHA256\(\),', native, re.S)
    if hop is None or capture is None or native.count('type nodeChainExecutionLatencyHop struct {') != 1:
        raise AssertionError('actual execution capture ABI changed')
    fields = re.findall(r'`json:"([a-z0-9_]+)"`', capture.group(1))
    if fields != ['schema', 'source_sha256', 'config_sha256', 'generation_sha256', 'selected_execution', 'nodes']:
        raise AssertionError('actual execution capture field inventory changed')
    measurement = (ROOT/'internal/mobilemultihop/node_chain_execution_measurement.go').read_text()
    for label in ('Cumulative %s path through custom node %d of %d → Cloudflare edge', 'Cumulative %s path through node %d of %d'):
        if measurement.count(label) != 1:
            raise AssertionError('actual selected-execution response label changed')
    return GO.replace('/*ACTUAL_HOP_TYPE*/', hop.group(0)).replace('/*ACTUAL_CAPTURE_TYPE*/', capture.group(1))


GO = r'''package main
import("bufio";"crypto/sha256";"encoding/base64";"encoding/hex";"encoding/json";"fmt";"os";"strings";"time";
 "router-vpn/internal/nativeopenvpn";"router-vpn/internal/hopmeasure")
/*ACTUAL_HOP_TYPE*/
func digest(s string) string {h:=sha256.Sum256([]byte(s));return hex.EncodeToString(h[:])}
func encoded(v any)string{b,e:=json.Marshal(v);if e!=nil{panic("fixture encoding failed")};return string(b)}
func fixtures(){
 rows:=[]map[string]any{}
 for _,shape:=range []struct{count int; imported bool}{{2,false},{3,false},{4,false},{5,false},{6,false},{7,false},{8,false},{3,true},{4,true},{8,true}}{
  for _,selection:=range []struct{requested,selected string}{{"server","server"},{"auto","local"},{"auto","server"}}{
   key:=fmt.Sprintf("%d/%t/%s/%s",shape.count,shape.imported,selection.requested,selection.selected)
   source,config,generation:=digest(key+"/actual-source"),digest(key+"/actual-config"),digest(key+"/actual-generation")
   nodes:=make([]nodeChainExecutionLatencyHop,shape.count)
   for i:=range nodes {role,kind:="intermediate","private-node";if i==0{role="entry"}else if i==shape.count-1{role="exit"};if shape.imported&&i==shape.count-2{kind="public-path"};nodes[i]=nodeChainExecutionLatencyHop{fmt.Sprintf("node_%d",i),i,role,kind}}
   capture:=encoded(/*ACTUAL_CAPTURE_TYPE*/{1,source,config,generation,selection.selected,nodes})
   receipts,statuses,ordinary:=[]string{},[]string{},[]string{}
   for i,node:=range nodes {
    label:=fmt.Sprintf("Cumulative %s path through node %d of %d",selection.selected,i+1,shape.count)
    metric,endpoint:="routed-private-response-including-connection",""
    if node.Kind=="public-path"{label=fmt.Sprintf("Cumulative %s path through custom node %d of %d → Cloudflare edge",selection.selected,i+1,shape.count);metric="routed-https-response-after-tls";endpoint="https://"+hopmeasure.PublicHost+"/__down?bytes=1"}
    result:=hopmeasure.Result{ID:node.NodeID,Role:node.Role,Kind:node.Kind,Label:label,Ready:true,Benchmark:&hopmeasure.LatencyBenchmark{Schema:1,Measurement:metric,Endpoint:endpoint,Attempts:hopmeasure.LatencyBenchmarkSamples,Failed:0,Distribution:&hopmeasure.Latency{Samples:hopmeasure.LatencyBenchmarkSamples,Min:1,Median:2,Average:2.5,P90:4,Max:5,Jitter:1},TrimmedMean:2.4}}
    request:=digest(fmt.Sprintf("%s/%d",key,i))[:32]
    receipt:=hopmeasure.OrderedLatencyReceipt{Schema:1,SourceSHA256:source,ConfigSHA256:config,GenerationSHA256:generation,Position:i,NodeID:node.NodeID,Request:request,MeasuredAt:time.Now().UnixMilli()-10000,Result:result}
    receipts=append(receipts,encoded(receipt));statuses=append(statuses,encoded(hopmeasure.Status{Request:request,Stage:"complete",Complete:true,Drained:true,Results:[]hopmeasure.Result{result}}))
    receipt.Result.Label=strings.Replace(label,"Cumulative "+selection.selected+" ","Cumulative ",1);ordinary=append(ordinary,encoded(receipt))
   }
   rows=append(rows,map[string]any{"key":key,"count":shape.count,"imported":shape.imported,"requested":selection.requested,"selected":selection.selected,"capture":capture,"receipts":receipts,"statuses":statuses,"ordinary":ordinary})
  }
 }
 fmt.Println(encoded(rows))
}
func main(){if len(os.Args)!=2{os.Exit(2)};switch os.Args[1]{case "--fixtures":fixtures();case "--validate-stream":
 scan:=bufio.NewScanner(os.Stdin);scan.Buffer(make([]byte,4096),90<<20);out:=bufio.NewWriter(os.Stdout)
 for scan.Scan(){raw,e:=base64.StdEncoding.DecodeString(scan.Text());if e==nil{e=nativeopenvpn.ValidatePrivateNodeJSON(string(raw))};if e==nil{fmt.Fprintln(out,"OK")}else{fmt.Fprintln(out,"REJECT")};if out.Flush()!=nil{os.Exit(3)}}
 if scan.Err()!=nil{os.Exit(4)}
 default:os.Exit(2)}}
'''

CONTEXT = r'''package android.content;
public final class Context {private final java.io.File directory;public Context(java.io.File directory){this.directory=directory;}
 public Context getApplicationContext(){return this;}public java.io.File getFilesDir(){return directory;}}
'''

LIBBOX = r'''package io.nekohasekai.libbox;
import java.io.*;import java.nio.charset.StandardCharsets;import java.util.Base64;import java.util.concurrent.TimeUnit;
public final class Libbox {
 private static Process child;private static BufferedWriter input;private static BufferedReader output;public static int calls,rejections;
 public static synchronized void routerValidatePrivateNodeJSON(String raw)throws Exception{
  if(child==null){String image=System.getenv("ROUTERVPN_EXECUTION_DATA_VALIDATOR");if(image==null)throw new IllegalStateException("actual JSON validator absent");
   child=new ProcessBuilder(image,"--validate-stream").redirectError(ProcessBuilder.Redirect.INHERIT).start();input=new BufferedWriter(new OutputStreamWriter(child.getOutputStream(),StandardCharsets.UTF_8));output=new BufferedReader(new InputStreamReader(child.getInputStream(),StandardCharsets.UTF_8));}
  calls++;input.write(Base64.getEncoder().encodeToString(raw.getBytes(StandardCharsets.UTF_8)));input.newLine();input.flush();String reply=output.readLine();
  if("REJECT".equals(reply)){rejections++;throw new IllegalArgumentException("actual private JSON validator rejected fixture");}
  if(!"OK".equals(reply))throw new IllegalStateException("actual private JSON validator lost its protocol");
 }
 public static synchronized void close()throws Exception{if(child==null)return;input.close();if(!child.waitFor(5,TimeUnit.SECONDS)){child.destroyForcibly();child.waitFor();throw new IllegalStateException("actual validator did not join");}if(child.exitValue()!=0||output.readLine()!=null)throw new IllegalStateException("actual validator failed or returned foreign output");output.close();child=null;}
}
'''

FILES = r'''package com.eabusham.routervpn;
import java.io.*;import java.nio.file.*;
/** Explicit Java-filesystem/atomic-publication fault boundary. This fixture
 * does not claim execution of Android's Os.rename/fsync/private-inode code. */
final class AndroidPrivateFileStore {
 static int writes,removes,failWrites,failReads;static Runnable afterWrite;
 static synchronized byte[] read(File file,int maximum)throws Exception{if(failReads>0){failReads--;throw new IOException("fixture read fault");}if(Files.isSymbolicLink(file.toPath())||!file.isFile())throw new IOException("fixture nonregular file");byte[] bytes=Files.readAllBytes(file.toPath());if(bytes.length<1||bytes.length>maximum)throw new IOException("fixture read size");return bytes;}
 static synchronized void write(File file,byte[] bytes,int maximum)throws Exception{writes++;if(failWrites>0){failWrites--;throw new IOException("fixture write fault");}if(bytes==null||bytes.length<1||bytes.length>maximum)throw new IOException("fixture write size");Files.createDirectories(file.toPath().getParent());Path temporary=Files.createTempFile(file.toPath().getParent(),"owned-fixture-",".tmp");try{Files.write(temporary,bytes);Files.move(temporary,file.toPath(),StandardCopyOption.ATOMIC_MOVE,StandardCopyOption.REPLACE_EXISTING);}finally{Files.deleteIfExists(temporary);}Runnable action=afterWrite;afterWrite=null;if(action!=null)action.run();}
 static synchronized void remove(File file,int maximum)throws Exception{removes++;Files.deleteIfExists(file.toPath());}
 static synchronized void reset(){writes=removes=failWrites=failReads=0;afterWrite=null;}
}
'''

HARNESS = r'''package com.eabusham.routervpn;
import android.content.Context;import io.nekohasekai.libbox.Libbox;import org.json.*;
import java.nio.file.*;import java.nio.charset.StandardCharsets;import java.util.*;
public final class ExecutionFiftyDataTest {
 static int checks;static JSONArray fixtures;static Path work;
 interface Action{void run()throws Exception;}
 static void check(boolean value,String why){checks++;if(!value)throw new AssertionError(why);}
 static Exception refused(Action action,String why)throws Exception{checks++;try{action.run();}catch(Exception error){return error;}throw new AssertionError(why);}
 static String hash(char c){return String.valueOf(c).repeat(64);}
 static Context context(String key)throws Exception{Path dir=work.resolve(key);Files.createDirectory(dir);return new Context(dir.toFile());}
 static Path file(Context c){return c.getFilesDir().toPath().resolve(AndroidOrderedExecutionLatencyStore.FILE_NAME);}
 static JSONObject fixture(boolean imported,String requested,String selected,int count)throws Exception{for(int i=0;i<fixtures.length();i++){JSONObject row=fixtures.getJSONObject(i);if(row.getBoolean("imported")==imported&&row.getInt("count")==count&&row.getString("requested").equals(requested)&&row.getString("selected").equals(selected))return row;}throw new AssertionError("fixture matrix entry missing");}
 static AndroidOrderedExecutionLatencyStore.Entry entry(JSONObject row,int position)throws Exception{return entry(row,position,hash('d'),hash('e'));}
 static AndroidOrderedExecutionLatencyStore.Entry entry(JSONObject row,int position,String source,String config)throws Exception{
  AndroidOrderedExecutionLatencyCapture capture=new AndroidOrderedExecutionLatencyCapture(row.getString("capture"));
  AndroidOrderedLatencyStore.Record record=new AndroidOrderedLatencyStore.Record(row.getJSONArray("receipts").getString(position),row.getString("selected"));
  return new AndroidOrderedExecutionLatencyStore.Entry(source,config,row.getString("requested"),capture,record);
 }
 static AndroidOrderedExecutionLatencyStore.Entry newer(AndroidOrderedExecutionLatencyStore.Entry original,char request)throws Exception{
  JSONObject root=new JSONObject(original.raw),receipt=new JSONObject(root.getString("receipt"));receipt.put("request_id",String.valueOf(request).repeat(32));receipt.put("measured_at",receipt.getLong("measured_at")+1000);root.put("receipt",receipt.toString());return new AndroidOrderedExecutionLatencyStore.Entry(root.toString());
 }
 static byte[] storeBytes(AndroidOrderedExecutionLatencyStore.Entry...entries)throws Exception{JSONArray list=new JSONArray();for(var entry:entries)list.put(entry.raw);return new JSONObject().put("schema",1).put("records",list).toString().getBytes(StandardCharsets.UTF_8);}
 static AndroidOrderedExecutionLatencyStore.Entry load(Context c,AndroidOrderedExecutionLatencyStore.Entry e)throws Exception{return AndroidOrderedExecutionLatencyStore.load(c,e.namespaceSource,e.namespaceConfig,e.requested,e.capture.selected,e.record.position,e.record.node,e.record.kind);}
 static void matrix()throws Exception{
  check(fixtures.length()==30,"native ABI fixture matrix truncated");int nodes=0;Set<String> shapes=new HashSet<>();
  for(int n=0;n<fixtures.length();n++){
   JSONObject row=fixtures.getJSONObject(n);String selected=row.getString("selected"),requested=row.getString("requested"),raw=row.getString("capture");
   AndroidOrderedExecutionLatencyCapture capture;try{capture=new AndroidOrderedExecutionLatencyCapture(raw);}catch(Exception error){throw new AssertionError("complete imported metadata refused",error);}capture.requireSelection(requested,selected);
   check(capture.raw.equals(raw)&&capture.nodes.size()==row.getInt("count"),"native capture bytes/count changed");
   refused(()->capture.nodes.clear(),"capture inventory is mutable");
   shapes.add(row.getInt("count")+"/"+row.getBoolean("imported")+"/"+requested+"/"+selected);
   for(int i=0;i<capture.nodes.size();i++){
    var node=capture.nodes.get(i);String receipt=row.getJSONArray("receipts").getString(i),status=row.getJSONArray("statuses").getString(i);
    AndroidOrderedLatencyStore.Record record;
    try{record=new AndroidOrderedLatencyStore.Record(receipt,selected);}catch(Exception error){throw new AssertionError("selected execution label was rejected",error);}
    try{capture.requireRecord(record);}catch(Exception error){throw new AssertionError("selected execution public label lost its original position",error);}capture.requireNode(i,node.id,node.role,node.kind,capture.nodes.size());
    check(record.raw.equals(receipt)&&record.selectedExecution.equals(selected)&&record.label.equals(capture.label(i)),"native receipt bytes/selected label changed");
    check(record.detail().contains("Selected execution: "+(selected.equals("server")?"Server":"Local")),"historical detail lost exact selected execution");
    var completed=AndroidOrderedLatencyStore.completed(status,receipt,record.request,capture.source,capture.config,i,node.id,node.kind,selected);
    check(completed.raw.equals(receipt)&&completed.generation.equals(capture.generation),"completion changed the native receipt");
    var e=entry(row,i);check(e.capture.raw.equals(raw)&&e.record.raw.equals(receipt)&&!e.namespaceSource.equals(e.capture.source),"preparation namespace replaced the native projection");
    Context c=context("matrix-"+n+"-"+i);AndroidOrderedExecutionLatencyStore.save(c,e,()->{});
    var saved=load(new Context(c.getFilesDir()),e);check(saved!=null&&saved.capture.raw.equals(raw)&&saved.record.raw.equals(receipt)&&saved.raw.equals(e.raw),"historical restart changed exact native strings");
    check(Arrays.equals(saved.record.raw.getBytes(StandardCharsets.UTF_8),receipt.getBytes(StandardCharsets.UTF_8)),"native receipt bytes were reserialized");nodes++;
   }
  }
  check(nodes==150&&shapes.size()==30,"all paired/imported node positions were not exercised");
 }
 static void captureRefusals()throws Exception{
  JSONObject row=fixture(false,"server","server",3);String raw=row.getString("capture");
  String duplicate=raw.replaceFirst("\\{","{\"schema\":1,");
  refused(()->new AndroidOrderedExecutionLatencyCapture(duplicate),"duplicate raw capture accepted");
  for(String fault:List.of("schema","source","config","generation","selected","unknown","missing","null","nodes-short","nodes-long","node-duplicate","node-position","node-role","node-kind","public-entry","public-exit","public-long","node-unknown","trailing","oversized")){
   JSONObject value=new JSONObject(raw);JSONArray nodes=value.getJSONArray("nodes");String changed;
   switch(fault){
    case "schema":value.put("schema",2);break;case "source":value.put("source_sha256","foreign");break;case "config":value.put("config_sha256",hash('F'));break;case "generation":value.put("generation_sha256",true);break;
    case "selected":value.put("selected_execution","auto");break;case "unknown":value.put("credential","must-not-be-history");break;case "missing":value.remove("generation_sha256");break;case "null":value.put("source_sha256",JSONObject.NULL);break;
    case "nodes-short":value.put("nodes",new JSONArray().put(nodes.get(0)));break;case "nodes-long":for(int i=3;i<9;i++)nodes.put(new JSONObject(nodes.getJSONObject(1).toString()).put("position",i).put("node_id","node_"+i));break;
    case "node-duplicate":nodes.getJSONObject(1).put("node_id",nodes.getJSONObject(0).getString("node_id"));break;case "node-position":nodes.getJSONObject(1).put("position",2);break;case "node-role":nodes.getJSONObject(1).put("role","exit");break;case "node-kind":nodes.getJSONObject(1).put("kind","public-node");break;
    case "public-entry":nodes.getJSONObject(0).put("kind","public-path");break;case "public-exit":nodes.getJSONObject(2).put("kind","public-path");break;
    case "public-long":value=new JSONObject(fixture(false,"server","server",4).getString("capture"));value.getJSONArray("nodes").getJSONObject(1).put("kind","public-path");break;case "node-unknown":nodes.getJSONObject(1).put("endpoint","private");break;
   }
   changed=value.toString();if(fault.equals("trailing"))changed+="{}";if(fault.equals("oversized"))changed+=" ".repeat(AndroidOrderedExecutionLatencyCapture.MAX_BYTES);
   final String candidate=changed;refused(()->new AndroidOrderedExecutionLatencyCapture(candidate),"invalid execution capture accepted: "+fault);
  }
  var local=new AndroidOrderedExecutionLatencyCapture(fixture(false,"auto","local",3).getString("capture"));
  refused(()->local.requireSelection("server","local"),"Server request borrowed Compare Local capture");
  refused(()->local.requireSelection("local","local"),"ordinary Local request entered execution history");
  refused(()->local.requireSelection("auto","server"),"selected result changed after capture");
 }
 static void receiptRefusals()throws Exception{
  JSONObject row=fixture(true,"auto","server",3);var capture=new AndroidOrderedExecutionLatencyCapture(row.getString("capture"));String original=row.getJSONArray("receipts").getString(1);
  for(String fault:List.of("source","config","generation","request","position","node","role","kind","label-local","label-ordinary","ready","samples","attempts","failed","metric","endpoint","extra","timestamp","nonfinite","negative","jitter","percentile")){
   JSONObject value=new JSONObject(original),result=value.getJSONObject("result"),benchmark=result.getJSONObject("benchmark"),distribution=benchmark.getJSONObject("distribution");
   switch(fault){
    case "source":value.put("source_sha256",hash('a'));break;case "config":value.put("config_sha256",hash('b'));break;case "generation":value.put("generation_sha256",hash('f'));break;case "request":value.put("request_id","A".repeat(32));break;
    case "position":value.put("position",0);break;case "node":value.put("node_id","other");result.put("node_id","other");break;case "role":result.put("role","entry");break;case "kind":result.put("kind","private-node");break;
    case "label-local":result.put("label",result.getString("label").replace("server","local"));break;case "label-ordinary":result.put("label",result.getString("label").replace("server ",""));break;case "ready":result.put("ready",false);break;
    case "samples":distribution.put("samples",49);break;case "attempts":benchmark.put("attempts",49);break;case "failed":benchmark.put("failed",1);break;case "metric":benchmark.put("measurement",AndroidOrderedLatencyStore.PRIVATE);break;case "endpoint":benchmark.put("endpoint","https://example.com/");break;
    case "extra":result.put("idle",new JSONObject());break;case "timestamp":value.put("measured_at",System.currentTimeMillis()+120000);break;case "nonfinite":distribution.put("average_ms","NaN");break;case "negative":distribution.put("min_ms",0);break;case "jitter":distribution.put("jitter_ms",10);break;case "percentile":distribution.put("p90_ms",1);break;
   }
   String altered=value.toString();refused(()->{var record=new AndroidOrderedLatencyStore.Record(altered,"server");capture.requireRecord(record);},fault.equals("generation")?"receipt generation substitution accepted":"invalid execution receipt accepted: "+fault);
  }
  AndroidOrderedLatencyStore.Record record=new AndroidOrderedLatencyStore.Record(original,"server");String status=row.getJSONArray("statuses").getString(1);
  for(String fault:List.of("request","complete","drained","stage","failure","empty","many","result")){
   JSONObject value=new JSONObject(status);
   switch(fault){case "request":value.put("request_id","0".repeat(32));break;case "complete":value.put("complete",false);break;case "drained":value.put("drained",false);break;case "stage":value.put("stage","draining");break;case "failure":value.put("failure","failed");break;case "empty":value.put("results",new JSONArray());break;case "many":value.getJSONArray("results").put(value.getJSONArray("results").get(0));break;case "result":value.getJSONArray("results").getJSONObject(0).getJSONObject("benchmark").put("trimmed_mean_ms",2.5);break;}
   String changed=value.toString();refused(()->AndroidOrderedLatencyStore.completed(changed,original,record.request,capture.source,capture.config,1,record.node,record.kind,"server"),fault.equals("result")?"status/result substitution accepted":"incomplete native status accepted: "+fault);
  }
 }
 static void ordinaryBoundary()throws Exception{
  JSONObject row=fixture(false,"server","server",3);String execution=row.getJSONArray("receipts").getString(2),ordinary=row.getJSONArray("ordinary").getString(2);
  refused(()->new AndroidOrderedLatencyStore.Record(execution),"ordinary parser accepted selected execution label");
  var original=new AndroidOrderedLatencyStore.Record(ordinary);check(original.selectedExecution.isEmpty()&&original.raw.equals(ordinary),"original ordinary Record grammar changed");
  refused(()->new AndroidOrderedLatencyStore.Record(ordinary,"server"),"execution parser accepted ordinary label");
  Context c=context("ordinary");AndroidOrderedLatencyStore.save(c,original,()->{});
  var e=entry(row,2);AndroidOrderedExecutionLatencyStore.save(c,e,()->{});
  check(!AndroidOrderedLatencyStore.FILE_NAME.equals(AndroidOrderedExecutionLatencyStore.FILE_NAME),"execution reused ordinary history file");
  check(AndroidOrderedLatencyStore.load(c,original.source,original.config,2,original.node,original.kind).raw.equals(ordinary),"execution history overwrote ordinary history");
  check(load(c,e).record.raw.equals(execution),"ordinary history overwrote selected history");
 }
 static void history()throws Exception{
  Context c=context("history");var server=entry(fixture(false,"server","server",3),2);var compare=entry(fixture(false,"auto","server",3),2);var local=entry(fixture(false,"auto","local",3),2);
  AndroidOrderedExecutionLatencyStore.save(c,server,()->{});AndroidOrderedExecutionLatencyStore.save(c,compare,()->{});AndroidOrderedExecutionLatencyStore.save(c,local,()->{});
  try{check(load(c,server).raw.equals(server.raw),"Server history mixed Compare setting");}catch(Exception error){throw new AssertionError("Server history mixed Compare setting",error);}
  check(load(c,compare).raw.equals(compare.raw)&&load(c,local).raw.equals(local.raw),"Compare selected executions mixed history");
  check(AndroidOrderedExecutionLatencyStore.load(c,hash('a'),server.namespaceConfig,"server","server",2,server.record.node,server.record.kind)==null,"history crossed preparation source");
  check(AndroidOrderedExecutionLatencyStore.load(c,server.namespaceSource,hash('b'),"server","server",2,server.record.node,server.record.kind)==null,"history crossed preparation config");
  check(AndroidOrderedExecutionLatencyStore.load(c,server.namespaceSource,server.namespaceConfig,"server","server",1,"node_1","private-node")==null,"history crossed node position");
  byte[] previous=Files.readAllBytes(file(c));refused(()->AndroidOrderedExecutionLatencyStore.save(c,server,()->{}),"duplicate native request republished");check(Arrays.equals(previous,Files.readAllBytes(file(c))),"duplicate changed history");
  JSONObject old=new JSONObject(server.raw),receipt=new JSONObject(old.getString("receipt"));receipt.put("request_id","0".repeat(32));receipt.put("measured_at",receipt.getLong("measured_at")-1);old.put("receipt",receipt.toString());var older=new AndroidOrderedExecutionLatencyStore.Entry(old.toString());
  refused(()->AndroidOrderedExecutionLatencyStore.save(c,older,()->{}),"older native receipt replaced newer history");check(Arrays.equals(previous,Files.readAllBytes(file(c))),"older result changed history");
  for(String fault:List.of("namespace","requested","selected","capture","receipt","unknown","duplicate")){
   JSONObject value=new JSONObject(server.raw);String altered;
   switch(fault){case "namespace":value.put("namespace_source_sha256","bad");break;case "requested":value.put("requested_execution","local");break;case "selected":value.put("requested_execution","server").put("capture",fixture(false,"auto","local",3).getString("capture"));break;case "capture":value.put("capture",new JSONObject());break;case "receipt":value.put("receipt",JSONObject.NULL);break;case "unknown":value.put("route_capability",true);break;}
   altered=value.toString();if(fault.equals("duplicate"))altered=altered.replaceFirst("\\{","{\"schema\":1,");final String text=altered;refused(()->new AndroidOrderedExecutionLatencyStore.Entry(text),"invalid historical envelope accepted: "+fault);
  }
 }
 static void rollback()throws Exception{
  var baseline=entry(fixture(false,"server","server",3),2);var next=newer(baseline,'1');var replacement=newer(next,'2');
  for(String fault:List.of("first-guard","second-guard","final-guard","write","readback","new-file","replacement","rollback-error")){
   Context c=context("rollback-"+fault);AndroidPrivateFileStore.reset();if(!fault.equals("new-file"))AndroidOrderedExecutionLatencyStore.save(c,baseline,()->{});
   byte[] before=Files.exists(file(c))?Files.readAllBytes(file(c)):null;int[] guards={0};byte[] other=storeBytes(replacement);
   if(fault.equals("write"))AndroidPrivateFileStore.failWrites=1;
   if(fault.equals("readback"))AndroidPrivateFileStore.afterWrite=()->AndroidPrivateFileStore.failReads=1;
   if(fault.equals("replacement"))AndroidPrivateFileStore.afterWrite=()->{try{Files.write(file(c),other);}catch(Exception e){throw new RuntimeException(e);}};
   if(fault.equals("rollback-error"))AndroidPrivateFileStore.afterWrite=()->AndroidPrivateFileStore.failWrites=1;
   Exception failure=refused(()->AndroidOrderedExecutionLatencyStore.save(c,next,()->{guards[0]++;if(fault.equals("first-guard")&&guards[0]==1||fault.equals("second-guard")&&guards[0]==2||List.of("final-guard","new-file","rollback-error").contains(fault)&&guards[0]==3)throw new IllegalStateException("original guard retired");}),fault.equals("final-guard")?"stale final guard accepted history":"failed storage transaction accepted: "+fault);
   if(fault.equals("replacement")){check(Arrays.equals(other,Files.readAllBytes(file(c))),"rollback overwrote replacement writer");check(load(c,replacement).raw.equals(replacement.raw),"replacement writer did not remain readable");}
   else if(fault.equals("rollback-error")){check(failure.getSuppressed().length==1,"rollback failure was silently accepted");}
   else if(before==null){check(!Files.exists(file(c)),"cancelled first writer left a new history");}
   else{check(Arrays.equals(before,Files.readAllBytes(file(c))),"failed storage transaction changed prior bytes: "+fault);}
   AndroidPrivateFileStore.reset();
  }
 }
 static void bounds()throws Exception{
  var e=entry(fixture(false,"server","server",2),0);Context c=context("bounds");
  for(String fault:List.of("unknown","schema","duplicate-key","duplicate-record","non-string","invalid-utf8","empty")){
   JSONArray entries=new JSONArray().put(e.raw);JSONObject root=new JSONObject().put("schema",1).put("records",entries);byte[] bytes;
   if(fault.equals("unknown"))root.put("native_owner",true);if(fault.equals("schema"))root.put("schema",2);if(fault.equals("duplicate-record"))entries.put(e.raw);if(fault.equals("non-string"))entries.put(new JSONObject(e.raw));
   String text=root.toString();if(fault.equals("duplicate-key"))text=text.replaceFirst("\\{","{\"schema\":1,");bytes=text.getBytes(StandardCharsets.UTF_8);if(fault.equals("invalid-utf8"))bytes=new byte[]{(byte)0xff};if(fault.equals("empty"))bytes=new byte[0];Files.write(file(c),bytes);
   byte[] preserved=bytes;refused(()->load(c,e),"malformed persisted history accepted: "+fault);check(Arrays.equals(preserved,Files.readAllBytes(file(c))),"history read rewrote malformed bytes");
  }
  JSONArray records=new JSONArray();for(int i=0;i<AndroidOrderedLatencyStore.MAX_RECORDS;i++){JSONObject row=new JSONObject(e.raw).put("namespace_source_sha256",String.format(Locale.ROOT,"%064x",i+1));records.put(new AndroidOrderedExecutionLatencyStore.Entry(row.toString()).raw);}
  byte[] maximum=new JSONObject().put("schema",1).put("records",records).toString().getBytes(StandardCharsets.UTF_8);Files.write(file(c),maximum);
  refused(()->AndroidOrderedExecutionLatencyStore.save(c,e,()->{}),"bounded historical inventory overflow accepted");check(Arrays.equals(maximum,Files.readAllBytes(file(c))),"overflow replaced prior history");
 }
 public static void main(String[] args)throws Exception{
  String family=args.length==0?"all":args[0];List<String> all=List.of("matrix","capture-refusals","receipt-refusals","ordinary-boundary","history","rollback","bounds");check(args.length<=1&&(family.equals("all")||all.contains(family)),"unknown fixture family");
  work=Path.of(System.getenv("ROUTERVPN_EXECUTION_DATA_WORK"));fixtures=new JSONArray(Files.readString(Path.of(System.getenv("ROUTERVPN_EXECUTION_DATA_FIXTURES"))));
  try{for(String name:all)if(family.equals("all")||family.equals(name)){switch(name){case "matrix":matrix();break;case "capture-refusals":captureRefusals();break;case "receipt-refusals":receiptRefusals();break;case "ordinary-boundary":ordinaryBoundary();break;case "history":history();break;case "rollback":rollback();break;case "bounds":bounds();break;}System.out.println("Execution fifty data passed: "+name);}check(Libbox.calls>0,"actual private JSON validator was never called");System.out.println("Android execution fifty data: "+checks+" checks; actual JSON validator calls "+Libbox.calls+"; filesystem/native owners remain explicit boundaries.");}
  finally{Libbox.close();}
 }
}
'''

CONTROLS = (
    ('complete-public-position', 'AndroidOrderedExecutionLatencyCapture', '"public-path".equals(kind)&&(members.length()<3||i!=members.length()-2)', '"public-path".equals(kind)&&(members.length()!=3||i!=1)', 'matrix', 'complete imported metadata refused'),
    ('complete-public-label', 'AndroidOrderedExecutionLatencyCapture', '?"custom node "+(position+1)+" of "+nodes.size()+" → Cloudflare edge"', '?"custom node 2 of 3 → Cloudflare edge"', 'matrix', 'selected execution public label lost its original position'),
    ('raw-json', 'AndroidOrderedExecutionLatencyCapture', 'io.nekohasekai.libbox.Libbox.routerValidatePrivateNodeJSON(raw);', '', 'capture-refusals', 'duplicate raw capture accepted'),
    ('selected', 'AndroidOrderedExecutionLatencyCapture', '||"server".equals(requested)&&!"server".equals(selected)', '||false', 'capture-refusals', 'Server request borrowed Compare Local capture'),
    ('generation', 'AndroidOrderedExecutionLatencyCapture', '||!generation.equals(record.generation)', '', 'receipt-refusals', 'receipt generation substitution accepted'),
    ('ordinary', 'AndroidOrderedLatencyStore', 'Record(String raw)throws Exception { this(raw, ""); }', 'Record(String raw)throws Exception { this(raw, "server"); }', 'ordinary-boundary', 'ordinary parser accepted selected execution label'),
    ('status-result', 'AndroidOrderedLatencyStore', 'if(!same(results.getJSONObject(0),new JSONObject(record.raw).getJSONObject("result")))throw invalid();', 'if(false)throw invalid();', 'receipt-refusals', 'status/result substitution accepted'),
    ('history-setting', 'AndroidOrderedExecutionLatencyStore', 'return source+":"+config+":"+requested+":"+selected+":"+position', 'return source+":"+config+":"+selected+":"+position', 'history', 'Server history mixed Compare setting'),
    ('final-guard', 'AndroidOrderedExecutionLatencyStore', 'throw new IllegalStateException("The execution history changed before durable readback.");\n                guard.require();', 'throw new IllegalStateException("The execution history changed before durable readback.");', 'rollback', 'stale final guard accepted history'),
    ('rollback-owner', 'AndroidOrderedExecutionLatencyStore', 'if(file.exists()&&Arrays.equals(written,AndroidPrivateFileStore.read(file,AndroidOrderedLatencyStore.MAX_STORE)))', 'if(file.exists())', 'rollback', 'rollback overwrote replacement writer'),
)


def main():
    before = sources()
    originals = {name: (JAVA/(name+'.java')).read_text() for name in NAMES}
    for _, name, anchor, _, _, _ in CONTROLS:
        if originals[name].count(anchor) != 1:
            raise AssertionError('the exact data-store causal anchor changed')
    go, javac, java = (Path(shutil.which(name) or '') for name in ('go', 'javac', 'java'))
    jar = Path(os.environ.get('ANDROID_JSON_JAR', '/usr/share/java/com.android.json.jar'))
    if any(not path.is_file() for path in (go, javac, java, jar)):
        raise AssertionError('the actual Go compiler, JDK and Android JSON jar are required')
    tools = {str(path): identity(path) for path in (go, javac, java, jar, Path(sys.executable))}
    def check():
        if sources() != before or {path: identity(path) for path in map(Path, tools)} != {Path(path): value for path, value in tools.items()}:
            raise AssertionError('frozen source or actual tools changed')
    with tempfile.TemporaryDirectory(prefix='routervpn-execution-data-') as temporary:
        work = Path(temporary); src = work/'src'; classes = work/'classes'; classes.mkdir()
        helper = work/'private-json-fixture'; main_go = work/'main.go'; main_go.write_text(go_source())
        overlay = work/'overlay.json'; overlay.write_text(json.dumps({'Replace': {str(ROOT/'cmd/router-agent/main.go'): str(main_go)}}))
        go_env = dict(os.environ, GOTOOLCHAIN='local', GOWORK='off', GOFLAGS='-p=1 -mod=readonly', GOMAXPROCS='1', GOMEMLIMIT='768MiB')
        execute([go, 'build', '-mod=readonly', '-p', '1', '-overlay', overlay, '-o', helper, './cmd/router-agent/main.go'], 120, env=go_env)
        helper_identity = identity(helper)
        fixture_bytes = execute([helper, '--fixtures'], 10).encode(); fixtures = work/'fixtures.json'; fixtures.write_bytes(fixture_bytes); fixtures.chmod(0o600)
        if len(json.loads(fixture_bytes)) != 30:
            raise AssertionError('the actual Go metadata fixture inventory changed')
        strict = re.findall(r'^    static String strictText\(byte\[\] bytes\) throws Exception \{.*\}$', (JAVA/'AndroidTorProfile.java').read_text(), re.M)
        if len(strict) != 1:
            raise AssertionError('the original Android UTF-8 decoder changed')
        copied = {'android/content/Context.java': CONTEXT, NATIVE+'Libbox.java': LIBBOX,
                  APP+'AndroidPrivateFileStore.java': FILES,
                  APP+'AndroidTorProfile.java': 'package com.eabusham.routervpn;import java.nio.charset.StandardCharsets;final class AndroidTorProfile {\n'+strict[0]+'\n}',
                  APP+'ExecutionFiftyDataTest.java': HARNESS}
        copied.update({APP+name+'.java': text for name, text in originals.items()})
        for name, text in copied.items():
            path = src/name; path.parent.mkdir(parents=True, exist_ok=True); path.write_text(text)
        compiler = [javac, '-J-Xmx512m', '-J-XX:ActiveProcessorCount=1']
        runtime_command = [java, '-Xmx512m', '-XX:ActiveProcessorCount=1']
        execute([*compiler, '--release', '17', '-encoding', 'UTF-8', '-proc:none', '-cp', jar, '-d', classes, *sorted(src.rglob('*.java'))], 60)
        env = dict(os.environ, ROUTERVPN_EXECUTION_DATA_VALIDATOR=str(helper), ROUTERVPN_EXECUTION_DATA_FIXTURES=str(fixtures))
        runtime = work/'positive'; runtime.mkdir(); env['ROUTERVPN_EXECUTION_DATA_WORK'] = str(runtime)
        output = execute([*runtime_command, '-cp', os.pathsep.join((str(classes), str(jar))), 'com.eabusham.routervpn.ExecutionFiftyDataTest'], 120, env=env)
        actual = re.findall(r'^Execution fifty data passed: (.+)$', output, re.M)
        if tuple(actual) != FAMILIES or len(re.findall(r'^Android execution fifty data: [0-9]+ checks; actual JSON validator calls [0-9]+; filesystem/native owners remain explicit boundaries\.$', output, re.M)) != 1:
            raise AssertionError('the complete data-store case inventory did not pass')
        print(output, end='')
        for label, name, anchor, replacement, family, witness in CONTROLS:
            check()
            target = work/('mutation-'+label)/(name+'.java'); target.parent.mkdir(); target.write_text(originals[name].replace(anchor, replacement))
            altered = work/('classes-'+label); shutil.copytree(classes, altered)
            cp = os.pathsep.join((str(altered), str(jar)))
            execute([*compiler, '--release', '17', '-encoding', 'UTF-8', '-proc:none', '-cp', cp, '-d', altered, target], 45)
            runtime = work/('case-'+label); runtime.mkdir(); env['ROUTERVPN_EXECUTION_DATA_WORK'] = str(runtime)
            rejected = execute([*runtime_command, '-cp', cp, 'com.eabusham.routervpn.ExecutionFiftyDataTest', family], 30, env=env, expected=1)
            if 'java.lang.AssertionError: '+witness not in rejected or re.search(r'(^|\n)Android execution fifty data:', rejected):
                raise AssertionError('the intended execution-data causal witness was absent: '+label)
            if identity(helper) != helper_identity or fixtures.read_bytes() != fixture_bytes:
                raise AssertionError('the actual validator or original metadata bytes changed')
            check(); print('Execution fifty data causal control rejected: '+label)
        check()
    receipt = dict(schema=1, accepted=True, source=before, tools=tools, source_after=sources(), families=list(FAMILIES),
                   native_metadata_shapes=30, original_node_positions=150, controls=[row[0] for row in CONTROLS], phases=PHASES,
                   actual_private_json_validator=True, actual_native_receipt_serializer=True,
                   measured_network_samples=False, android_atomic_syscalls=False, native_owner_adoption=False, device_accepted=False,
                   rollback_scope='Shared synchronized app transaction and exact byte guard; no OS-wide same-byte inode CAS claim.')
    destination = os.environ.get('ROUTERVPN_ANDROID_EXECUTION_DATA_RECEIPT')
    if destination:
        path = Path(destination)
        with path.open('x') as stream: json.dump(receipt, stream, indent=2); stream.write('\n')
    print('Android execution fifty data: all seven families and ten compiled causal controls passed')


if __name__ == '__main__': main()
