#!/usr/bin/env python3
"""Execute post-drain candidate proposal saves with real stores/shared compiler.

Only the preparation's graph-drain authority and native measurement callbacks
are doubled here. The integrated preparation gate owns the actual handoff.
"""
from pathlib import Path
import os
import shutil
import subprocess
import sys
import test_android_node_candidate_prefix_capture as prefix_capture
import test_android_node_candidates as candidates

ROOT=candidates.ROOT
HARNESS=r'''package com.eabusham.routervpn;
import java.nio.file.*;import java.util.*;import java.util.concurrent.*;import org.json.*;import io.nekohasekai.libbox.*;
public final class NodeCandidateProfileHarness {
 static int checks;
 static void check(boolean value,String message){checks++;if(!value)throw new AssertionError(message);}
 interface Work{void run()throws Exception;}
 static void reject(Work work,String message)throws Exception{try{work.run();}catch(Exception expected){checks++;return;}throw new AssertionError(message);}
 // This deliberately exposes separate native-candidate and outer-graph joins.
 // A completed TCP receipt is never itself evidence that the graph is DOWN.
 static final class Authority implements AndroidNodeCandidateProfile.SavedResultAuthority {
  final AndroidNodeCandidateResult original;boolean drained,current=true;int calls,rejectAt;
  Authority(AndroidNodeCandidateResult result){original=result;}
  public void requireCurrent(AndroidNodeCandidateResult result){calls++;if(!drained||!current||result!=original||calls==rejectAt)throw new IllegalStateException("Original detached preparation is not current");}
 }
 static final class Captured implements AutoCloseable {
  final NodeChainCaptureHarness.Fixture fixture;final AndroidNodeChainSession session;final Object lease;
  final CountDownLatch completed=new CountDownLatch(1),finished=new CountDownLatch(1);
  AndroidNodeCandidateMeasurement owner;AndroidNodeCandidateResult result;Authority authority;
  AndroidNodeCandidateProfile temporary,live;Throwable preparationFailure;
  Captured(Path root,String method)throws Exception{this(root,method,method.contains("aes-128")?"3/":method.contains("aes-256")?"4/mixed-awg":"8/mixed-awg","local");}
  Captured(Path root,String method,String key,String requested)throws Exception{
   fixture=new NodeChainCaptureHarness.Fixture(root,key);
   if(!requested.equals("local"))fixture.chooseExecution(requested);
   var entry=NodeCandidateHarness.custom(method);new AndroidStandardExitStore(fixture.context).save(entry);
   session=new AndroidNodeChainSession(fixture.profiles.currentOrderedPath());
   var catalog=new AndroidNodeCandidateCatalog(fixture.context,session,session.source.members.size()-3);lease=AndroidMTUMeasurementGate.acquire();
   RouterNodeChainCandidateMeasurement.holdClose=true;
   owner=AndroidNodeCandidateMeasurement.startBorrowed(catalog,lease,new AndroidNodeCandidateMeasurement.Callback(){
    public void changed(List<AndroidNodeCandidateResult> rows,String detail){}
    public void completed(AndroidNodeCandidateMeasurement operation,List<AndroidNodeCandidateResult> rows)throws Exception{
     owner=operation;
     try{
      result=rows.stream().filter(row->row.id.equals(entry.id)).findFirst().orElseThrow();authority=new Authority(result);
      reject(()->AndroidNodeCandidateProfile.captureTemporary(operation,result,null),"temporary proposal accepted no detached authority");
      var constructor=AndroidNodeCandidateResult.class.getDeclaredConstructors()[0];constructor.setAccessible(true);
      var copied=(AndroidNodeCandidateResult)constructor.newInstance(result.id,result.name,result.source,result.measuredAt,result.expiresAt,result.score);
      reject(()->AndroidNodeCandidateProfile.captureTemporary(operation,copied,authority),"temporary proposal accepted a copied unadmitted result");
      live=new AndroidNodeCandidateProfile(operation,result);
      temporary=AndroidNodeCandidateProfile.captureTemporary(operation,result,authority);
     }catch(Throwable failed){preparationFailure=failed;}finally{completed.countDown();}
    }
    public void finished(Throwable failure){if(failure!=null)preparationFailure=failure;finished.countDown();}
   });
   boolean ready=completed.await(20,TimeUnit.SECONDS);if(preparationFailure!=null)throw new AssertionError("Candidate proposal failed for "+key+"/"+requested,preparationFailure);
   check(ready&&temporary!=null,"temporary proposal was not captured while original measurement was live");
  }
  void joinCandidate()throws Exception{
   RouterNodeChainCandidateMeasurement.holdClose=false;
   check(finished.await(10,TimeUnit.SECONDS)&&owner.joined(),"original candidate worker did not join");
   check(AndroidMTUMeasurementGate.owns(lease),"candidate join released the still-owned outer graph lease");
  }
  void drainGraph(){session.current=false;AndroidMTUMeasurementGate.release(lease);authority.drained=true;}
  public void close()throws Exception{RouterNodeChain.afterConfig=null;RouterNodeChainCandidateMeasurement.holdClose=false;owner.cancel();finished.await(10,TimeUnit.SECONDS);AndroidMTUMeasurementGate.release(lease);}
 }
 static void saveAfterDown(Path root,String method)throws Exception{saveAfterDown(root,method,method.contains("aes-128")?"3/":method.contains("aes-256")?"4/mixed-awg":"8/mixed-awg","local");}
 static void saveAfterDown(Path root,String method,String key,String requested)throws Exception{
  try(var capture=new Captured(root,method,key,requested)){
   var f=capture.fixture;var before=new NodeChainCaptureHarness.State(f);
   capture.authority.drained=true;
   reject(()->capture.temporary.save(f.context,"Before candidate join"),"temporary proposal saved before original candidate join");
   capture.authority.drained=false;capture.joinCandidate();
   reject(()->capture.live.save(f.context,"Closed live receipt"),"ordinary live proposal survived closed measurement");
   reject(()->AndroidNodeCandidateProfile.captureTemporary(capture.owner,capture.result,capture.authority),"closed measurement minted a new temporary proposal");
   reject(()->capture.temporary.save(f.context,"Before graph drain"),"temporary proposal saved before original graph drain authority");
   check(!Files.exists(f.rows),"unjoined temporary proposal wrote profile storage");
   capture.drainGraph();
   var saved=capture.temporary.save(f.context,"Detached "+method);
   check(saved.mode.equals("shadowsocks"),"detached save lost its actual final transport");
   JSONArray rows=new JSONObject(Files.readString(f.rows)).getJSONArray("profiles");JSONObject row=rows.getJSONObject(0);
   check(rows.length()==1&&row.getJSONArray("multihop_nodes").length()==capture.session.source.members.size(),"detached proposal truncated the complete original path");
   JSONArray savedMembers=row.getJSONArray("multihop_nodes");
   for(int position=0;position<savedMembers.length();position++){
    var member=savedMembers.getJSONObject(position);boolean replaced=position==capture.owner.catalog.prefix+1;
    check(member.getString("id").equals(replaced?capture.result.id:capture.session.source.members.get(position).profileId),"detached proposal changed a different original position");
    check(member.getString("mode").equals(replaced?"shadowsocks":capture.session.source.modes.get(position)),"detached proposal changed a retained original mode");
   }
   check(row.getString("multihop_execution").equals(capture.session.source.execution),"detached proposal changed requested execution");
   check(!row.toString().contains("api_token")&&!row.toString().contains("wg_private_key")&&!row.toString().contains(NodeCandidateHarness.custom(method).secret),"detached profile copied original private credentials");
   var after=new NodeChainCaptureHarness.State(f);
   for(Path path:before.files.keySet())if(!path.equals(f.rows))check(Arrays.equals(before.files.get(path),after.files.get(path)),"detached Save edited an original node source");
   check(before.preferences.equals(after.preferences),"detached Save changed selected or active path preferences");
   byte[] original=Files.readAllBytes(f.rows);
   capture.authority.current=false;
   reject(()->capture.temporary.save(f.context,"Retired detached receipt"),"retired detached authority saved a profile");
   capture.authority.current=true;capture.authority.rejectAt=capture.authority.calls+3;
   reject(()->capture.temporary.save(f.context,"Changed during append"),"late detached authority change wrote profile storage");
   check(Arrays.equals(original,Files.readAllBytes(f.rows)),"rejected detached save changed stored profiles");
   capture.authority.rejectAt=0;
   var expiry=AndroidNodeCandidateResult.class.getDeclaredField("expiresAt");expiry.setAccessible(true);expiry.setLong(capture.result,System.currentTimeMillis()-1);
   reject(()->capture.temporary.save(f.context,"Expired detached receipt"),"expired detached result saved a profile");
   check(Arrays.equals(original,Files.readAllBytes(f.rows)),"expired result wrote profile storage");
   f.profiles.load(saved.id);
   try(var compiled=AndroidNodeChainCapture.compile(f.profiles.currentOrderedPath())){check(new JSONObject(compiled.launchInput).getInt("schema")==2&&compiled.memberInputs.size()==capture.session.source.members.size(),"detached saved path did not compile its complete original length on normal explicit Load");}
  }
 }
 static void cancellationDuringCompile(Path root)throws Exception{
  var f=new NodeChainCaptureHarness.Fixture(root,"2/");var session=new AndroidNodeChainSession(f.profiles.currentOrderedPath());var catalog=new AndroidNodeCandidateCatalog(f.context,session,0);
  CountDownLatch ready=new CountDownLatch(1),finished=new CountDownLatch(1);var results=new java.util.concurrent.atomic.AtomicReference<List<AndroidNodeCandidateResult>>();
  var operation=AndroidNodeCandidateMeasurement.start(catalog,new AndroidNodeCandidateMeasurement.Callback(){public void changed(List<AndroidNodeCandidateResult> rows,String detail){if(!rows.isEmpty()){results.set(rows);ready.countDown();}}public void finished(Throwable failure){finished.countDown();}});
  try{
   check(ready.await(10,TimeUnit.SECONDS),"live compiler cancellation fixture received no result");
   var result=results.get().get(0);RouterNodeChain.afterConfig=operation::cancel;
   reject(()->AndroidNodeCandidateProfile.captureTemporary(operation,result,new Authority(result)),"temporary proposal ignored cancellation during original graph compile");
  }finally{RouterNodeChain.afterConfig=null;operation.cancel();check(finished.await(10,TimeUnit.SECONDS),"compile-cancelled candidate did not join");}
 }
 static void unavailable(Work work,String fragment)throws Exception{
  try{work.run();}catch(AndroidNodeCandidateProfile.ProposalUnavailable expected){check(expected.getMessage().contains(fragment),"wrong deterministic Save reason: "+expected.getMessage());return;}
  throw new AssertionError("known incompatible replacement did not retain a typed Save reason");
 }
 static void fatal(Work work,String message)throws Exception{
  try{work.run();}catch(AndroidNodeCandidateProfile.ProposalUnavailable wrong){throw new AssertionError(message,wrong);}catch(Exception expected){checks++;return;}
  throw new AssertionError(message);
 }
 static void proposalRows(Path root,String key,int prefix,String fault)throws Exception{
  var f=new NodeChainCaptureHarness.Fixture(root,key);var entry=NodeCandidateHarness.custom("2022-blake3-aes-256-gcm");new AndroidStandardExitStore(f.context).save(entry);
  // Retain an independently generated real paired SS source when its original
  // identity is outside this captured path; never rewrite keys or identities.
  String extraID="";
  if(f.members.size()<8){var originals=new JSONObject(Files.readString(Path.of(System.getenv("ROUTERVPN_ANDROID_CHAIN_FIXTURE")))).getJSONArray("8/mixed-awg");var extra=originals.getJSONObject(7);var imported=f.nodes.importBundle(extra.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8));check(f.nodes.activeId().equals(imported.id),"candidate fixture did not retain the shipping import selection");f.nodes.select(f.control().id);check(f.nodes.activeId().equals(f.control().id),"candidate fixture did not restore the original selected control");extraID=NodeChainCaptureHarness.profile(extra).getString("id");}
  final String independentPairedID=extraID;
  var source=f.profiles.currentOrderedPath();
  if(fault.equals("draft")){
   var draft=new AndroidOrderedPathSelection(f.nodes,f.profiles);draft.removePrefix(0);source=draft.candidateDraftCapture(prefix).call();
  }
  var session=new AndroidNodeChainSession(source,fault.equals("draft")?prefix:-1);var catalog=new AndroidNodeCandidateCatalog(f.context,session,prefix);
  Object lease=AndroidMTUMeasurementGate.acquire();CountDownLatch completed=new CountDownLatch(1),finished=new CountDownLatch(1);var failure=new java.util.concurrent.atomic.AtomicReference<Throwable>();
  RouterNodeChainCandidateMeasurement.holdClose=true;
  var owner=AndroidNodeCandidateMeasurement.startBorrowed(catalog,lease,new AndroidNodeCandidateMeasurement.Callback(){
   public void changed(List<AndroidNodeCandidateResult> rows,String detail){}
   public void completed(AndroidNodeCandidateMeasurement operation,List<AndroidNodeCandidateResult> rows)throws Exception{
    try{
     var measured=rows.stream().filter(row->row.id.equals(entry.id)).findFirst().orElseThrow();
     var duplicate=rows.stream().filter(row->row.id.equals(session.source.members.get(session.source.members.size()-1).profileId)).findFirst().orElseThrow();
     var authority=new Authority(measured);
     if(fault.equals("draft")){
      unavailable(()->AndroidNodeCandidateProfile.captureTemporary(operation,measured,authority),"unsaved ordered draft");
      unavailable(()->new AndroidNodeCandidateProfile(operation,measured),"unsaved ordered draft");
     }else if(fault.equals("compiler")){
      RouterNodeChain.afterConfig=()->{throw new IllegalStateException("Native config read failed after actual compilation");};
      fatal(()->AndroidNodeCandidateProfile.captureTemporary(operation,measured,authority),"unexpected compiler failure became a Save incompatibility");
     }else if(fault.equals("cancel")){
      operation.cancel();fatal(()->AndroidNodeCandidateProfile.captureTemporary(operation,duplicate,authority),"cancelled original owner became a Save incompatibility");
     }else if(fault.equals("source")){
      Path original=f.members.get(0).file.toPath();byte[] before=Files.readAllBytes(original);Files.write(original,Arrays.copyOf(before,before.length+1));
      fatal(()->AndroidNodeCandidateProfile.captureTemporary(operation,duplicate,authority),"mutated original source became a Save incompatibility");
     }else{
      unavailable(()->AndroidNodeCandidateProfile.captureTemporary(operation,duplicate,new Authority(duplicate)),"duplicates");
      boolean completePosition=prefix==session.source.members.size()-3;
      if(fault.equals("hysteria")){
       check(completePosition&&session.source.modes.get(session.source.modes.size()-1).equals("hysteria2"),"unsupported-final check did not start from a valid captured Hysteria2 path");
       unavailable(()->AndroidNodeCandidateProfile.captureTemporary(operation,measured,authority),"requires a paired Shadowsocks final; the saved final mode is hysteria2");
      }else{
       var valid=AndroidNodeCandidateProfile.captureTemporary(operation,measured,authority);
       check(valid!=null && valid.description.contains(entry.id),"known incompatible row prevented a separate complete compiled proposal");
       if(!completePosition)check(valid.description.contains(session.source.members.get(prefix+2).profileId),"earlier literal SS2022 proposal lost its original suffix");
      }
      if(!independentPairedID.isEmpty()){
       var paired=rows.stream().filter(row->row.id.equals(independentPairedID)).findFirst().orElseThrow();
       unavailable(()->AndroidNodeCandidateProfile.captureTemporary(operation,paired,new Authority(paired)),"intermediate hop");
      }
      check(!Files.exists(f.rows),"proposal classification saved a profile without explicit Save");
     }
    }catch(Throwable error){failure.set(error);}finally{completed.countDown();}
   }
   public void finished(Throwable error){finished.countDown();}
  });
  try{check(completed.await(20,TimeUnit.SECONDS),"proposal classification did not complete");if(failure.get()!=null)throw new AssertionError("actual proposal classification failed: "+key+"/"+prefix+"/"+fault,failure.get());}
  finally{RouterNodeChain.afterConfig=null;RouterNodeChainCandidateMeasurement.holdClose=false;owner.cancel();check(finished.await(10,TimeUnit.SECONDS)&&owner.joined(),"proposal classification did not join original candidate owner");AndroidMTUMeasurementGate.release(lease);}
 }
 static void recursiveProposal(NodeChainCaptureHarness.Fixture f,AndroidNodeStore.ChainCapture source,int position,String independent)throws Exception{
  var session=new AndroidNodeChainSession(source,-1);var catalog=new AndroidNodeCandidateCatalog(f.context,session,position);
  var done=new CountDownLatch(1);var failure=new java.util.concurrent.atomic.AtomicReference<Throwable>();
  var lease=AndroidMTUMeasurementGate.acquire();String finalId=source.members.get(source.members.size()-1).profileId;
  var captured=new java.util.concurrent.atomic.AtomicReference<AndroidNodeCandidateProfile>();
  var authority=new java.util.concurrent.atomic.AtomicReference<Authority>();
  var operation=AndroidNodeCandidateMeasurement.startBorrowed(catalog,lease,new AndroidNodeCandidateMeasurement.Callback(){
   public void changed(List<AndroidNodeCandidateResult> rows,String detail){}
   public void completed(AndroidNodeCandidateMeasurement operation,List<AndroidNodeCandidateResult> rows)throws Exception{
    var result=rows.stream().filter(row->row.id.equals(finalId)).findFirst().orElseThrow();
    if(position<source.members.size()-2){
     unavailable(()->new AndroidNodeCandidateProfile(operation,result),"duplicates");
     if(!independent.isEmpty()){
      var next=rows.stream().filter(row->row.id.equals(independent)).findFirst().orElseThrow();
      authority.set(new Authority(next));captured.set(AndroidNodeCandidateProfile.captureTemporary(operation,next,authority.get()));
     }
    }
    else check(new AndroidNodeCandidateProfile(operation,result).description.contains(finalId),"recursive final proposal lost its private source");
   }
   public void finished(Throwable error){failure.set(error);done.countDown();}
  });
  try{
   check(done.await(30,TimeUnit.SECONDS)&&operation.joined(),"recursive candidate batch did not drain");
   if(failure.get()!=null)throw new AssertionError("recursive candidate result was discarded",failure.get());
   if(captured.get()!=null){
    session.current=false;AndroidMTUMeasurementGate.release(lease);
    authority.get().drained=true;var saved=captured.get().save(f.context,"Second private intermediate");f.profiles.load(saved.id);
    var changed=f.profiles.currentOrderedPath();check(changed.members.size()==source.members.size()+1,"second private proposal lost its suffix");
    for(int i=0;i<changed.members.size();i++)check(changed.members.get(i).profileId.equals(i==position+1?independent:source.members.get(i>position+1?i-1:i).profileId),"recursive Save substituted original member at "+i);
    try(var original=AndroidNodeChainCapture.compile(changed)){
     var roles=new JSONArray(original.plan.extendedLocalRolesJSON());check(roles.length()==changed.members.size(),"deep restored native roles missing");
     for(int i=0;i<roles.length();i++)check(roles.getString(i).equals(changed.members.get(i).imported?"public-path":"private-node"),"deep native original role differs at "+i);
    }
   }
  }finally{operation.cancel();AndroidMTUMeasurementGate.release(lease);session.capture.close();}
 }
 static void responseProfile(Path root,String variant)throws Exception{
  boolean earlier=!variant.equals("final"), draft=variant.equals("draft"), conflict=variant.equals("conflict"),hostname=variant.equals("deep-hostname"),deep=variant.equals("deep")||hostname;
  var f=new NodeChainCaptureHarness.Fixture(root,"2/awg-fast");
  var bundles=new JSONObject(Files.readString(Path.of(System.getenv("ROUTERVPN_ANDROID_CHAIN_FIXTURE"))));
  var independent=bundles.getJSONArray("8/mixed-awg").getJSONObject(7);
  var next=f.nodes.importBundle(independent.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8));
  String nextId=NodeChainCaptureHarness.profile(independent).getString("id");
  String anotherId="";
  if(deep){var another=bundles.getJSONArray("7/mixed-awg").getJSONObject(6);f.nodes.importBundle(another.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8));anotherId=NodeChainCaptureHarness.profile(another).getString("id");}
  f.nodes.select(f.control().id);
  var exits=new AndroidStandardExitStore(f.context);
  var first=hostname?NodeChainCaptureHarness.hostnameEntry("2022-blake3-aes-256-gcm"):NodeCandidateHarness.custom("2022-blake3-aes-256-gcm");
  if(!hostname)first.policy.put("dns_mode","rescue").put("start_layer","off");
  exits.save(first);
  if(earlier){
   var second=AndroidStandardExitStore.copy(first);second.id="second-import";second.server="198.51.100.77";
   second.secret=Base64.getEncoder().encodeToString("b".repeat(32).getBytes(java.nio.charset.StandardCharsets.UTF_8));
   if(conflict){
    String asset=independent.getJSONObject("profiles").getJSONObject("shadowsocks").getString("sing-box.json");
    var config=new JSONObject(new String(Base64.getDecoder().decode(asset),java.nio.charset.StandardCharsets.UTF_8));
    second.secret=config.getJSONArray("outbounds").getJSONObject(0).getString("password");
   }
   exits.save(second);
  }
  var editor=new AndroidOrderedPathSelection(f.nodes,f.profiles);editor.addPrefix(first.id,"shadowsocks");
  if(earlier)editor.addPrefix("second-import","shadowsocks");
  if(deep){
   for(int i=2;i<7;i++){
    var additional=AndroidStandardExitStore.copy(first);additional.id="original-import-"+i;additional.server="198.51.100."+(90+i);
    additional.secret=Base64.getEncoder().encodeToString(String.valueOf((char)('m'+i)).repeat(32).getBytes(java.nio.charset.StandardCharsets.UTF_8));exits.save(additional);
   }
   // All imports must be captured from the same original catalog generation.
   editor=new AndroidOrderedPathSelection(f.nodes,f.profiles);editor.addPrefix(first.id,"shadowsocks");editor.addPrefix("second-import","shadowsocks");
   for(int i=2;i<7;i++)editor.addPrefix("original-import-"+i,"shadowsocks");
  }
  AndroidNodeStore.ChainCapture original;
  if(draft){
   var ui=new OrderedProductSurface(f);ui.editHop(editor,1);
   int action=Arrays.asList(ui.dialog.labels).indexOf("Measure candidates through this hop");
   check(action>=0,"earlier draft hop missing candidate measurement in editor");ui.choose(action);
   check(ui.measuredPrefix==1&&ui.measuredDraft!=null,"draft editor measured a different prefix");
   original=ui.measuredDraft.call();
  }else original=editor.save();
  var session=new AndroidNodeChainSession(original,draft?1:-1);var catalog=new AndroidNodeCandidateCatalog(f.context,session,1);
  check(catalog.measurement.equals("routed-candidate-response"),"original imported prefix lost its native response metric");
  var before=new NodeChainCaptureHarness.State(f);var done=new CountDownLatch(1);
  var failure=new java.util.concurrent.atomic.AtomicReference<Throwable>();
  var proposal=new java.util.concurrent.atomic.AtomicReference<AndroidNodeCandidateProfile>();
  var authority=new java.util.concurrent.atomic.AtomicReference<Authority>();var lease=AndroidMTUMeasurementGate.acquire();
  var owner=AndroidNodeCandidateMeasurement.startBorrowed(catalog,lease,new AndroidNodeCandidateMeasurement.Callback(){
   public void changed(List<AndroidNodeCandidateResult> rows,String detail){}
   public void completed(AndroidNodeCandidateMeasurement operation,List<AndroidNodeCandidateResult> rows)throws Exception{
    var result=rows.stream().filter(r->r.id.equals(nextId)).findFirst().orElseThrow();
    authority.set(new Authority(result));
    if(conflict){
     unavailable(()->new AndroidNodeCandidateProfile(operation,result),"must be independent");
     unavailable(()->AndroidNodeCandidateProfile.captureTemporary(operation,result,authority.get()),"must be independent");
    }else{
     new AndroidNodeCandidateProfile(operation,result);
     proposal.set(AndroidNodeCandidateProfile.captureTemporary(operation,result,authority.get()));
    }
   }
   public void finished(Throwable error){failure.set(error);done.countDown();}
  });
  try{
   check(done.await(30,TimeUnit.SECONDS)&&owner.joined(),"authenticated candidate profile did not join");
   if(failure.get()!=null)throw new AssertionError("authenticated candidate proposal lost its measured row",failure.get());
   session.current=false;AndroidMTUMeasurementGate.release(lease);
   before.same(f,"private candidate proposal preview");
   if(!conflict){
    authority.get().drained=true;var saved=proposal.get().save(f.context,earlier?"Measured intermediate":"Measured final");
    var members=f.row().getJSONArray("multihop_nodes");
    var expectedIds=new ArrayList<String>();for(var member:original.members)expectedIds.add(member.profileId);
    if(earlier)expectedIds.add(2,nextId);else expectedIds.set(2,nextId);
    check(members.length()==expectedIds.size()&&f.nodes.activeId().equals(f.control().id),"private candidate Save changed the original length or active node");
    for(int i=0;i<members.length();i++)check(members.getJSONObject(i).getString("id").equals(expectedIds.get(i))
      &&members.getJSONObject(i).getString("mode").equals(i==0?"awg2-fast":"shadowsocks"),"private candidate changed a retained position or transport");
    f.profiles.load(saved.id);
    try(var reopened=AndroidNodeChainCapture.compile(f.profiles.currentOrderedPath())){
     check(reopened.plan!=null&&reopened.memberInputs.size()==expectedIds.size()&&f.nodes.activeId().equals(earlier?f.control().id:next.id),"saved authenticated candidate did not reopen through the native compiler");
     if(earlier){
      check(reopened.multipleImported&&!reopened.identityInputs.get(2).isEmpty()&&reopened.identityInputs.get(1).isEmpty()&&reopened.identityInputs.get(3).isEmpty(),"paired intermediate inherited an imported identity or lost its own");
      var loaded=f.profiles.currentOrderedPath();
      if(hostname){
       check(loaded.members.get(1).external().server.equals(first.server)&&loaded.members.get(1).external().policy.getString("dns_host").equals(first.policy.getString("dns_host")),"measured private intermediate replaced the original hostname resolver");
      }
      if(draft||hostname){
       for(int position:List.of(2,3)){
        var reopenedEditor=new AndroidOrderedPathSelection(f.nodes,f.profiles);
        check(reopenedEditor.canMeasureResponseThrough(position),"restored editor omitted recursive response position");
        var recaptured=reopenedEditor.candidateDraftCapture(position).call();
        var measuredSource=AndroidNodeCandidateCatalog.captureSources(f.context,recaptured,position);
        check(measuredSource.measurement.equals("routed-candidate-response"),"recursive draft captured an incorrect metric");
        try(var complete=AndroidNodeChainCapture.compile(recaptured,position);
            var closed=AndroidNodeCandidatePrefixCapture.compile(complete,position,measuredSource.inventory);
            var replay=AndroidNodeCandidatePrefixCapture.reopen(closed.launchInput,complete,position,measuredSource.inventory)){
         var meta=new JSONObject(closed.metadata);var proofs=meta.getJSONArray("prefixes");
         check(proofs.length()==position+1&&meta.getString("measurement").equals("routed-candidate-response")&&!meta.getBoolean("application_open")&&!meta.getBoolean("dns_open"),"recursive native plan did not preserve the exact closed prefix");
         check(!proofs.getJSONObject(2).optString("node_id").isEmpty()&&proofs.getJSONObject(1).getString("node_id").isEmpty()
           &&(position==2||proofs.getJSONObject(3).getString("node_id").isEmpty()),"recursive private proof was substituted with a public import");
         check(replay.config.equals(closed.config)&&replay.captureSHA256.equals(closed.captureSHA256),"recursive closed-prefix replay lost owner");
        }
        recursiveProposal(f,loaded,position,"");
       }
      }
      if(deep)recursiveProposal(f,loaded,2,anotherId);
      reject(()->AndroidNodeChainCapture.requireCompleteShape(loaded.members,loaded.modes,"server"),"Server borrowed a Local paired stream");
      reject(()->AndroidNodeChainCapture.requireCompleteShape(loaded.members,loaded.modes,"auto"),"Compare borrowed a Local paired stream");
     }
    }
   }
  }finally{owner.cancel();AndroidMTUMeasurementGate.release(lease);session.capture.close();}
 }
 public static void main(String[] args)throws Exception{
  try{Path root=Path.of(args[0]);
   if(args.length==2&&args[1].equals("response")){
    for(String variant:List.of("final","intermediate","draft","conflict","deep","deep-hostname"))responseProfile(root,variant);
    System.out.println("Android authenticated candidate profile: "+checks+" source, Save, reopen and refusal checks PASS");return;
   }
   if(args.length==2&&args[1].startsWith("rows-")){
    int count=Integer.parseInt(args[1].substring(5));String key=count==3?"3/":count+"/mixed-awg";
    proposalRows(root,key,count-3,"");if(count>3)proposalRows(root,key,0,"");
    if(count==3){for(String fault:List.of("compiler","cancel","source","draft"))proposalRows(root,key,0,fault);proposalRows(root,"3/hy2-awg-fast",0,"hysteria");}
    System.out.println("Android measured proposal rows "+count+": "+checks+" actual source, strict refusal and individual compiler checks PASS");return;
   }
   if(args.length==2&&args[1].equals("execution")){
    // This detached preparation only owns a Local graph. Selected Server and
    // Compare use the separate typed connected owner at entry position zero.
    for(String requested:List.of("server","auto"))for(String key:List.of("4/mixed-awg","8/mixed-awg")){
     var f=new NodeChainCaptureHarness.Fixture(root,key);f.chooseExecution(requested);
     var source=f.profiles.currentOrderedPath();check(requested.equals(source.execution),"saved preparation lost operator execution");
     var session=new AndroidNodeChainSession(source);var catalog=new AndroidNodeCandidateCatalog(f.context,session,source.members.size()-3);
     var before=new NodeChainCaptureHarness.State(f);var lease=AndroidMTUMeasurementGate.acquire();var done=new CountDownLatch(1);
     var rejected=new java.util.concurrent.atomic.AtomicReference<Throwable>();
     try{
      AndroidNodeCandidateMeasurement.startBorrowed(catalog,lease,new AndroidNodeCandidateMeasurement.Callback(){
       public void changed(List<AndroidNodeCandidateResult> rows,String detail){}
       public void completed(AndroidNodeCandidateMeasurement owner,List<AndroidNodeCandidateResult> rows){throw new AssertionError("Local double lent a score to a selected execution");}
       public void finished(Throwable error){rejected.set(error);done.countDown();}
      });
      check(done.await(10,TimeUnit.SECONDS)&&rejected.get() instanceof IllegalStateException&&rejected.get().getMessage().contains("cannot borrow a Local candidate owner"),"missing selected execution owner did not fail closed");
     }finally{AndroidMTUMeasurementGate.release(lease);}
     before.same(f,"unavailable detached selected execution");
     // Independently exercise the persistence boundary with the compiler's
     // original graph and an explicit source guard. No TCP result is claimed.
     f.profiles.appendOrderedProposal("Original execution storage",source.members,source.modes,requested,()->{
      try{source.requireCurrent();}catch(Exception stale){throw new IllegalStateException(stale);}
     });
     check(requested.equals(f.row().getString("multihop_execution")),"proposal storage changed requested execution");
    }
    System.out.println("Android detached selected execution: "+checks+" original source, storage and missing typed owner checks PASS");return;
   }
   for(String method:List.of("2022-blake3-aes-128-gcm","2022-blake3-aes-256-gcm","2022-blake3-chacha20-poly1305"))saveAfterDown(root,method);cancellationDuringCompile(root);System.out.println("Android detached candidate proposals: "+checks+" complete source, drain and explicit Save checks PASS");}
  finally{RouterNodeChain.afterConfig=null;RouterNodeChainCandidateMeasurement.holdClose=false;AndroidNodeCandidateMeasurement.cancelActive();}
 }
}'''


def prepare(src,app,java):
    prefix_capture.prepare(src,app,java)
    (app/'NodeCandidateProfileHarness.java').write_text(HARNESS)
    source=src/'io/nekohasekai/libbox/RouterNodeChain.java'
    raw=source.read_text()
    before=' public String config()throws Exception{return Libbox.call("chain-config",launchInput());}'
    after=' public static Runnable afterConfig; public String config()throws Exception{String config=Libbox.call("chain-config",launchInput());Runnable hook=afterConfig;afterConfig=null;if(hook!=null)hook.run();return config;}'
    assert raw.count(before)==1
    source.write_text(raw.replace(before,after))


def run_profiles(root,work,app,classes,jar,env):
    classpath=str(classes)+os.pathsep+str(jar)
    response_data=work/'candidate-response-profile';response_data.mkdir()
    subprocess.run(['java','-cp',classpath,'com.eabusham.routervpn.NodeCandidateProfileHarness',str(response_data),'response'],env=env,check=True,timeout=120)
    data=work/'candidate-profile-data';data.mkdir()
    subprocess.run(['java','-cp',classpath,'com.eabusham.routervpn.NodeCandidateProfileHarness',str(data)],env=env,check=True,timeout=120)
    execution_data=work/'candidate-profile-execution-data';execution_data.mkdir()
    subprocess.run(['java','-cp',classpath,'com.eabusham.routervpn.NodeCandidateProfileHarness',str(execution_data),'execution'],env=env,check=True,timeout=120)
    for count in (3,4,8):
        rows=work/('candidate-profile-rows-'+str(count));rows.mkdir()
        subprocess.run(['java','-cp',classpath,'com.eabusham.routervpn.NodeCandidateProfileHarness',str(rows),'rows-'+str(count)],env=env,check=True,timeout=120)
    controls=(
        ('!operation.joined()||','', 'temporary proposal saved before original candidate join'),
        ('savedAuthority.requireCurrent(result);','', 'temporary proposal saved before original graph drain authority'),
        ('try{requireSavedCurrent();}catch','try{}catch', 'late detached authority change wrote profile storage'),
        ('||!result.current(System.currentTimeMillis())','', 'expired detached result saved a profile'),
        ('            requireCurrent();}\n        finally {compiled.close();}', '            }\n        finally {compiled.close();}', 'temporary proposal ignored cancellation during original graph compile'),
    )
    original=(app/'AndroidNodeCandidateProfile.java').read_text()
    for index,(old,new,witness) in enumerate(controls):
        assert original.count(old)==1 and old!=new,old
        mutation=work/('candidate-profile-mutant-'+str(index));mutation.mkdir()
        source=mutation/'AndroidNodeCandidateProfile.java';source.write_text(original.replace(old,new))
        target=mutation/'classes';shutil.copytree(classes,target);classpath=str(target)+os.pathsep+str(jar)
        subprocess.run(['javac','--release','17','-cp',classpath,'-d',str(target),str(source)],check=True,timeout=60)
        data=mutation/'private';data.mkdir()
        failed=subprocess.run(['java','-cp',classpath,'com.eabusham.routervpn.NodeCandidateProfileHarness',str(data)],env=env,capture_output=True,text=True,timeout=120)
        assert failed.returncode!=0 and witness in failed.stderr,failed.stdout+failed.stderr
        print('Android detached proposal causal control rejected:',witness,flush=True)

    row_controls=(
        ('throw unavailable("This replacement duplicates a node retained in the saved path.");', 'throw new IllegalStateException("old duplicate batch failure");'),
        ('throw unavailable("The measured transport cannot replace a WireGuard or AmneziaWG intermediate hop.");', 'throw new IllegalStateException("old mode batch failure");'),
        ('if (replacement == sources.size()-1 || (!shadowsocks && replacement != sources.size()-2))', 'if (replacement != sources.size()-2) throw new IllegalStateException("old position batch failure"); if (replacement == sources.size()-1)'),
        ('throw unavailable("This imported intermediate transport requires a paired Shadowsocks final; the saved final mode is "+modes.get(modes.size()-1)+".");', 'throw new IllegalStateException("old final-family batch failure");'),
    )
    for index,(old,new) in enumerate(row_controls):
        assert original.count(old)==1
        mutation=work/('candidate-row-mutant-'+str(index));mutation.mkdir();source=mutation/'AndroidNodeCandidateProfile.java';source.write_text(original.replace(old,new))
        target=mutation/'classes';shutil.copytree(classes,target);classpath=str(target)+os.pathsep+str(jar)
        subprocess.run(['javac','--release','17','-cp',classpath,'-d',str(target),str(source)],check=True,timeout=60)
        data=mutation/'private';data.mkdir();family='rows-4' if index==2 else 'rows-3'
        failed=subprocess.run(['java','-cp',classpath,'com.eabusham.routervpn.NodeCandidateProfileHarness',str(data),family],env=env,capture_output=True,text=True,timeout=120)
        assert failed.returncode==1 and 'actual proposal classification failed:' in failed.stderr and 'old ' in failed.stderr,failed.stdout+failed.stderr
        print('Android proposal row causal control rejected:',index,flush=True)

    original_store=(app/'AndroidConnectionProfileStore.java').read_text()
    start=original_store.index('synchronized Record appendOrderedProposal(')
    end=original_store.index('\n    }',start)
    old='.put("multihop_execution",execution)'
    assert original_store[start:end].count(old)==1
    source=work/'candidate-execution-mutant'/'AndroidConnectionProfileStore.java';source.parent.mkdir()
    source.write_text(original_store[:start]+original_store[start:end].replace(old,'.put("multihop_execution","local")')+original_store[end:])
    target=source.parent/'classes';shutil.copytree(classes,target);classpath=str(target)+os.pathsep+str(jar)
    subprocess.run(['javac','--release','17','-cp',classpath,'-d',str(target),str(source)],check=True,timeout=60)
    data=source.parent/'private';data.mkdir()
    failed=subprocess.run(['java','-cp',classpath,'com.eabusham.routervpn.NodeCandidateProfileHarness',str(data),'execution'],env=env,capture_output=True,text=True,timeout=120)
    witness='proposal storage changed requested execution'
    assert failed.returncode==1 and ('AssertionError: '+witness) in failed.stderr,failed.stdout+failed.stderr
    print('Android detached proposal causal control rejected:',witness,flush=True)


def run(root,work,app,classes,jar,env,imported_only=False):
    env=candidates.generate_fixture(root,work,env)
    run_profiles(root,work,app,classes,jar,env)


if __name__=='__main__':
    candidates.chain.prepare_sources=prepare;candidates.chain.compiler_source=prefix_capture.compiler;candidates.chain.run=run
    sys.argv=[sys.argv[0],'--case-family','ordered-chain'];candidates.profiles.main()
