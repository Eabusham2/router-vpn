#!/usr/bin/env python3
"""Run shipping Android schema-six Local capture and profile transactions.

The Java/native boundary executes the real pure Go constructors. Storage faults
are explicit boundary doubles; this gate does not start a VPN or prove traffic.
Each phase and compiled causal control keeps a finite original-style bound.
"""
from pathlib import Path
import json
import os
import re
import shutil
import subprocess
import sys
import test_android_node_chain_capture as BASE

def compiler_source(source):
    source = BASE.compiler_source(source)
    marker = "case len(args)==2:"
    extra = 'case len(args)==2&&args[0]=="chain-independent-proofs":var chain *mobilemultihop.NodeChain;chain,err=mobilemultihop.ParseNodeChainLaunchInput(args[1]);if err==nil{var encoded []byte;encoded,err=json.Marshal(chain.ProofInventory());result=string(encoded)};'
    extra += 'case len(args)==3&&args[0]=="independent-candidate-metric":var chain *mobilemultihop.NodeChain;chain,err=mobilemultihop.ParseNodeChainLaunchInput(args[1]);if err==nil{var position int;_,err=fmt.Sscan(args[2],&position);if err==nil{result=chain.CandidatePrefixMeasurement(position)}};'
    assert source.count(marker) == 1
    return source.replace(marker, extra + marker)

PHASES = ("selected-execution","selected-extended-nine","selected-extended-sixteen","selected-fast-nine","selected-fast-sixteen","selected-strong-nine","selected-strong-sixteen","selected-fast-bounds","hostname-four","hostname-nine","hostname-sixteen", "adjacent", "separated", "single-interior", "maximum", "extended-nine", "extended-sixteen", "awg-fast", "awg-strong", "layers", "refusals", "rollback", "stale", "source-race", "compiler", "preview-receipts", "history", "custom-entry")
HARNESS = r'''package com.eabusham.routervpn;
import org.json.*;import java.io.*;import java.nio.file.*;import java.nio.charset.StandardCharsets;import java.util.*;
public final class MultipleImportedLocalHarness {
 static int checks;interface Checked{void run()throws Exception;}
 static void check(boolean value,String why){checks++;if(!value)throw new AssertionError(why);}
 static void reject(Checked action,String why)throws Exception{try{action.run();}catch(Exception expected){checks++;return;}throw new AssertionError(why);}
 static AndroidStandardExitStore.Entry imported(int position,String method)throws Exception{
  var value=new AndroidStandardExitStore.Entry();value.id=String.format("%032x",1000+position);value.name="Independent original SS "+position;
  value.protocol="shadowsocks";value.server="198.51.100."+(40+position);value.serverPort=21000+position;value.expectedPublicIp="203.0.113."+(40+position);value.method=method;
  byte[] key=new byte[method.contains("128")?16:32];Arrays.fill(key,(byte)(80+position));value.secret=Base64.getEncoder().encodeToString(key);
  value.policy.put("dns_mode","rescue").put("start_layer","off").put("kill_switch_policy",position%2==0?"always":"on-connect").put("home_lan_access",position%2!=0);
  return value;
 }
 static final class Fixture {
  final NodeChainCaptureHarness.Fixture paired;final AndroidStandardExitStore exits;final List<AndroidStandardExitStore.Entry> imports=new ArrayList<>();
  Fixture(Path root,String key,int count)throws Exception{
   paired=new NodeChainCaptureHarness.Fixture(root,key);exits=new AndroidStandardExitStore(paired.context);
   for(int i=0;i<count;i++){var source=imported(i,List.of("2022-blake3-aes-128-gcm","2022-blake3-aes-256-gcm","2022-blake3-chacha20-poly1305").get(i%3));exits.save(source);imports.add(source);}
  }
  AndroidOrderedPathSelection draft()throws Exception{return new AndroidOrderedPathSelection(paired.nodes,paired.profiles);}
  void addAll(AndroidOrderedPathSelection draft)throws Exception{for(var source:imports){check(draft.prefixModes(source.id).contains("shadowsocks"),"independent imported source omitted from original editor");draft.addPrefix(source.id,"shadowsocks");}}
  void change()throws Exception{
   paired.changePolicies();
   for(var original:imports){var source=exits.get(original.id);source.policy.put("home_lan_access",!original.policy.getBoolean("home_lan_access")).put("kill_switch_policy","off");exits.save(source);}
  }
 }
 static void verify(Fixture f,AndroidNodeStore.ChainCapture source,int schema)throws Exception{
  check(source.execution.equals("local")&&source.members.get(0).imported==(schema==7)&&!source.members.get(source.members.size()-1).imported,"Local graph lost its original physical entry or paired final");
  try(var captured=AndroidNodeChainCapture.compile(source)){
   JSONObject launch=new JSONObject(captured.launchInput),graph=new JSONObject(captured.config);JSONArray inputs=launch.getJSONArray("nodes"),identities=launch.getJSONArray("identity_sources"),proofs=new JSONArray(io.nekohasekai.libbox.Libbox.routerIndependentProofs(captured.launchInput));
   check(launch.getInt("schema")==schema&&inputs.length()==source.members.size()&&identities.length()==inputs.length(),"independent Local capture lost its complete schema or inventory");
   check(captured.plan!=null&&captured.socks==null&&captured.connect==null&&!captured.openVPN,"independent imports borrowed a typed native factory");
   Set<String> tags=new HashSet<>();String previous="";int importedCount=0;
   for(int i=0;i<inputs.length();i++){
    var member=source.members.get(i);check(inputs.getString(i).equals(captured.memberInputs.get(i))&&identities.getString(i).equals(captured.identityInputs.get(i)),"complete original member or identity readback changed");
    check(identities.getString(i).isEmpty()==member.imported,"imported source borrowed paired identity");
    JSONObject selected=null;JSONObject proof=proofs.getJSONObject(i);JSONArray values=graph.getJSONArray(member.imported||i==inputs.length()-1?"outbounds":"endpoints");
    check(proof.getInt("position")==i&&proof.getString("profile_id").equals(member.profileId),"proof inventory lost exact original position");
    if(member.imported){
     importedCount++;var original=member.external();JSONObject input=new JSONObject(inputs.getString(i));JSONObject capture=new JSONObject(input.getString("capture")),profile=capture.getJSONObject("profile");
     check(capture.getString("expected_public_ip").equals(original.expectedPublicIp)&&profile.getString("id").equals(original.id)&&!profile.has("node_proof_id")&&!profile.has("api_token")&&!profile.has("router_api"),"imported position borrowed another public or paired identity");
     for(int n=0;n<values.length();n++){JSONObject out=values.getJSONObject(n);if(original.server.equals(out.optString("server"))&&out.optInt("server_port")==original.serverPort)selected=out;}
     check(selected!=null&&selected.getString("password").equals(original.secret)&&selected.getString("method").equals(original.method)&&!selected.has("network")&&!selected.has("udp_over_tcp"),"imported position replaced original credentials or UDP source");
    }else{
     JSONObject input=new JSONObject(inputs.getString(i)),profile=new JSONObject(input.getString("profile_json"));
     check(profile.getString("node_proof_id").equals(member.proofId)&&profile.getString("api_token").equals(member.profile().getString("api_token")),"paired position lost its own private proof or token");
     for(int n=0;n<values.length();n++){JSONObject out=values.getJSONObject(n);if(out.optString("tag").equals(proof.getString("tag")))selected=out;}
     check(selected!=null,"paired position lost its original native closure");
    }
    check(selected.getString("tag").equals(proof.getString("tag")),"native closure borrowed another original proof tag");
    JSONObject outer=selected;
    if(outer.has("detour")&&!outer.getString("detour").equals(previous))outer=NodeChainCaptureHarness.tagged(graph.getJSONArray("outbounds"),outer.getString("detour"));
    if(i>0)check(outer.getString("detour").equals(previous),"complete graph skipped an original predecessor");
    else check(!outer.has("detour"),"physical entry gained another predecessor");
    previous=selected.getString("tag");check(tags.add(previous),"two independent positions borrowed one native tag");
   }
   JSONObject dns=graph.getJSONObject("dns"),resolver=NodeChainCaptureHarness.tagged(dns.getJSONArray("servers"),dns.getString("final"));
   check(importedCount==f.imports.size()&&graph.getJSONArray("inbounds").length()==1&&resolver.getString("detour").equals(previous)&&resolver.getString("server").equals(captured.finalProfile().getString("adguard_ipv4")),"imports replaced final Home DNS or system VPN ownership");
   try(var replay=AndroidNodeChainCapture.reopen(captured.launchInput,source)){check(replay.config.equals(captured.config)&&replay.launchInput.equals(captured.launchInput),"complete Local replay changed original source");}
   for(int position=0;position<inputs.length();position++)if(source.members.get(position).imported){final int at=position;
    JSONObject changed=new JSONObject(captured.launchInput);JSONArray replaced=changed.getJSONArray("nodes");replaced.put(at,inputs.getString(at==0?1:0));
    reject(()->{try(var ignored=AndroidNodeChainCapture.reopen(changed.toString(),source)){}},"replay accepted substituted imported source position");
   }
  }
 }
 static void roundtrip(Path root,String phase)throws Exception{
  String key=phase.equals("separated")?"4/mixed-awg":phase.equals("single-interior")?"3/":phase.startsWith("awg-")?"2/"+phase:"2/";int count=phase.equals("extended-nine")?7:phase.equals("extended-sixteen")?14:phase.equals("maximum")?6:phase.equals("single-interior")?1:2;
  var f=new Fixture(root,key,count);var draft=f.draft();try{f.addAll(draft);}catch(Exception failure){throw new AssertionError("complete independent Local source was refused",failure);}
  if(phase.equals("separated"))draft.movePrefix(3,1);
  if(phase.equals("single-interior"))draft.movePrefix(2,1);
  List<String> ids=new ArrayList<>();for(var member:draft.members())ids.add(member.source.id);
  check(draft.execution().equals("local"),"opening the original Local draft changed its saved execution");
  var source=draft.save();verify(f,source,6);
  if(count>=7)try(var live=AndroidNodeChainCapture.compile(source)){
   int selected=source.modes.size()-2;
   check(AndroidNodeChainCapture.responsePrefix(source.members,source.modes,selected,"local")&&"routed-candidate-response".equals(io.nekohasekai.libbox.Libbox.routerIndependentCandidateMetric(live.launchInput,selected)),"late imported UI disagreed with sealed native response capability");
   check(!AndroidNodeChainCapture.responsePrefix(source.members,source.modes,selected,"server")&&!AndroidNodeChainCapture.responsePrefix(source.members,source.modes,selected,"auto"),"late imported UI granted selected execution a Local owner");
   var mixed=new ArrayList<>(source.modes);mixed.set(selected,"wg");check(!AndroidNodeChainCapture.responsePrefix(source.members,mixed,selected,"local"),"late imported UI admitted a mixed original suffix");
  }
  var saved=f.paired.profiles.add("Every independent original import");String row=Files.readString(f.paired.rows);
  for(var original:f.imports)check(!row.contains(original.secret),"saved profile duplicated imported private credentials");
  check(!row.contains("api_token")&&!row.contains("sing-box.json"),"saved profile copied paired private source");
  f.change();f.paired.profiles.load(saved.id);var restored=f.paired.profiles.currentOrderedPath();
  for(int i=0;i<ids.size();i++)check(ids.get(i).equals(restored.members.get(i).id),"profile Load reordered complete original path");
  for(var original:f.imports){var loaded=f.exits.get(original.id);check(loaded.policy.getBoolean("home_lan_access")==original.policy.getBoolean("home_lan_access")&&loaded.policy.getString("kill_switch_policy").equals(original.policy.getString("kill_switch_policy")),"profile Load lost an earlier imported policy");check(loaded.secret.equals(original.secret)&&loaded.server.equals(original.server),"profile Load substituted original imported source");}
  verify(f,restored,6);
  f.paired.profiles.update(saved.id,"Updated complete imported set");f.paired.profiles.delete(saved.id);
  for(var original:f.imports)check(f.exits.get(original.id).secret.equals(original.secret),"profile Delete removed an original independent source");
 }
 static void mixedExtended(Path root,int n)throws Exception{
  var f=new Fixture(root,n==9?"3/":"3/awg-strong",n-3);var draft=f.draft();
  f.addAll(draft);var source=draft.save();verify(f,source,6);
  try(var captured=AndroidNodeChainCapture.compile(source)){
   check(captured.plan.extendedLocalNodeCount()==n&&captured.plan.extendedMixedLocalPacketCount()==2,"original native mixed packet boundary changed");
   int last=n-2;
   check(AndroidNodeChainCapture.responsePrefix(source.members,source.modes,last,"local")&&"routed-candidate-response".equals(io.nekohasekai.libbox.Libbox.routerIndependentCandidateMetric(captured.launchInput,last)),"late original mixed response not available");
   check(!AndroidNodeChainCapture.responsePrefix(source.members,source.modes,last,"server"),"Local mixed source borrowed selected execution");
   check("routed-tcp-connect".equals(io.nekohasekai.libbox.Libbox.routerIndependentCandidateMetric(captured.launchInput,1)),"second packet lost its original TCP bound");
   reject(()->draft.setExecution("server"),"mixed route admitted selected Server");reject(()->draft.setExecution("auto"),"mixed route admitted selected Compare");
  }
  var profile=f.paired.profiles.add("Original mixed route");f.change();
  f.paired.profiles.load(profile.id);var restored=f.paired.profiles.currentOrderedPath();verify(f,restored,6);
  check(restored.modes.equals(source.modes),"loading altered mixed original modes");
  for(int i=0;i<n;i++)check(restored.members.get(i).profileId.equals(source.members.get(i).profileId),"loading reordered an original mixed member");
  f.paired.profiles.update(profile.id,"Updated original mixed route");f.paired.profiles.delete(profile.id);
 }
 static void mixedLatePacket(Path root)throws Exception{
  var f=new Fixture(root,"16/",6);var draft=f.draft();
  while(draft.members().size()>10)draft.removePrefix(draft.members().size()-2);
  f.addAll(draft);var source=draft.save();verify(f,source,6);
  var pick=f.draft().candidateDraftCapture(8).call();
  try(var current=AndroidNodeChainCapture.compile(source);var scored=AndroidNodeChainCapture.compile(pick,8)){
   check(current.plan.extendedMixedLocalPacketCount()==9&&current.plan.extendedLocalNodeCount()==16,"native owner lost nine original packets");
   check(scored.sourceSHA256.equals(current.sourceSHA256)&&"routed-tcp-connect".equals(io.nekohasekai.libbox.Libbox.routerIndependentCandidateMetric(scored.launchInput,8)),"late packet chooser lost its complete original");
   check("routed-candidate-response".equals(io.nekohasekai.libbox.Libbox.routerIndependentCandidateMetric(scored.launchInput,14)),"late stream confused with packet authority");
   check(!AndroidNodeChainCapture.responsePrefix(pick.members,pick.modes,8,"local"),"packet chooser advertised stream responses");
  }
 }
 static void mixedHostname(Path root,int total)throws Exception{
  int paired=total==9?3:2,first=paired-1;
  var f=new Fixture(root,total==9?"3/mixed-awg":total==4?"2/awg-fast":"2/awg-strong",total-paired);
  var host=NodeChainCaptureHarness.hostnameEntry(f.imports.get(0).method);
  host.id=f.imports.get(0).id;host.serverPort=f.imports.get(1).serverPort;
  f.exits.save(host);f.imports.set(0,host);
  if(total==9){
   var layered=new Fixture(root,"4/mixed-awg",2);layered.exits.save(host);
   var guarded=layered.draft();guarded.addPrefix(host.id,"shadowsocks");
   check(!guarded.prefixModes(layered.imports.get(1).id).contains("shadowsocks"),"layered mixed route acquired the hostname resolver");
   reject(()->guarded.addPrefix(layered.imports.get(1).id,"shadowsocks"),"mixed hostname bypassed original packet Start Layer");
  }
  var draft=f.draft();f.addAll(draft);
  check(draft.members().size()==total,"editor truncated the original hostname route");
  reject(()->draft.movePrefix(first,first+1),"hostname moved past an original literal stream");
  for(String selection:List.of("server","auto"))reject(()->draft.setExecution(selection),"mixed hostname acquired selected execution");
  for(int position:new int[]{first,total-2}){
   check(draft.canMeasureResponseThrough(position),"mixed hostname candidate omitted original stream");
   var unsaved=draft.candidateDraftCapture(position).call();
   try(var preview=AndroidNodeChainCapture.compile(unsaved,position)){
    check("routed-candidate-response".equals(io.nekohasekai.libbox.Libbox.routerIndependentCandidateMetric(preview.launchInput,position)),
      "mixed hostname draft preview lost original response authority");
   }
  }
  var source=draft.save();verify(f,source,6);
  try(var live=AndroidNodeChainCapture.compile(source)){
   JSONObject member=new JSONObject(live.memberInputs.get(first)),privateCapture=new JSONObject(member.getString("capture"));
   JSONObject original=privateCapture.getJSONObject("profile");
   check(original.getString("endpoint").equals(host.server)&&original.getString("dns_host").equals(host.policy.getString("dns_host"))&&
     original.getInt("dns_port")==host.policy.getInt("dns_port")&&"tcp".equals(original.getString("dns_protocol"))&&!original.has("dns_bootstrap"),
     "mixed source changed its original hostname or captured resolver");
   JSONObject graph=new JSONObject(live.config),dns=graph.getJSONObject("dns");JSONArray proofs=new JSONArray(io.nekohasekai.libbox.Libbox.routerIndependentProofs(live.launchInput));
   JSONObject transport=NodeChainCaptureHarness.tagged(graph.getJSONArray("outbounds"),proofs.getJSONObject(first).getString("tag"));
   var excluded=transport.getJSONArray("routervpn_original_peer_exclusions");
   check(excluded.length()==1&&excluded.getString(0).equals(f.imports.get(1).server),"mixed hostname lost the original same-port peer exclusion");
   JSONObject resolver=NodeChainCaptureHarness.tagged(dns.getJSONArray("servers"),transport.getJSONObject("domain_resolver").getString("server"));
   check(resolver.getString("type").equals("tcp")&&resolver.getString("server").equals(host.policy.getString("dns_host"))
      &&resolver.getInt("server_port")==host.policy.getInt("dns_port")&&resolver.getString("detour").equals(proofs.getJSONObject(first-1).getString("tag"))
      &&!resolver.getString("tag").equals(dns.getString("final")),"mixed hostname resolver escaped its original packet predecessor");
   if(total>8){
    var roles=new JSONArray(live.plan.extendedLocalRolesJSON());
    for(int i=0;i<total;i++)check(roles.getString(i).equals(source.members.get(i).imported?"public-path":"private-node"),"hostname changed a member's original telemetry role");
   }
  }
  var named=f.paired.profiles.add("Mixed original hostname");f.change();f.paired.profiles.load(named.id);
  var restored=f.paired.profiles.currentOrderedPath();verify(f,restored,6);
  check(restored.members.get(first).profileId.equals(host.id)&&restored.members.get(first).external().server.equals(host.server)
    &&restored.members.get(first).external().policy.getString("dns_host").equals(host.policy.getString("dns_host")),
    "profile Load changed the original hostname or its resolver");
  var changed=f.exits.get(host.id);changed.policy.put("dns_host","10.81.0.54");f.exits.save(changed);
  reject(restored::requireCurrent,"changed original DNS resolver revived the old hostname capture");
 }
 static void selectedExecution(Path root,int total,String fixture)throws Exception{
  for(String requested:List.of("server","auto")){
   var f=new Fixture(root,fixture,total==0?2:total-2);
   var draft=f.draft();
   if(total>0)draft.setExecution(requested);
   f.addAll(draft);
   if(total==0){draft.movePrefix(2,1);draft.setExecution(requested);}
   var source=draft.save();var saved=f.paired.profiles.add("Complete "+requested+" imported route");
   try(var original=AndroidNodeChainCapture.compile(source);
       var chosen=AndroidNodeChainExecutionCapture.compile(original,requested)){
    if(fixture.equals("2/awg-fast") || fixture.equals("2/awg-strong")){
     String packetMode = fixture.equals("2/awg-strong") ? "awg2-strong" : "awg2-fast";
     var proof=new JSONArray(io.nekohasekai.libbox.Libbox.routerIndependentProofs(original.launchInput));
     check(proof.getJSONObject(0).getString("mode").equals(packetMode)&&proof.getJSONObject(0).getString("node_id").equals(source.members.get(0).proofId),"selected original AWG2 entry became another packet source");
     JSONObject originalBundle=new JSONObject(new String(source.members.get(0).bytes(),StandardCharsets.UTF_8));
     String raw=new String(Base64.getDecoder().decode(originalBundle.getJSONObject("profiles").getJSONObject(packetMode).getString("awg.conf")),StandardCharsets.UTF_8);
     String junkCount=raw.lines().filter(line->line.split("=",2)[0].trim().equals("Jc")).findFirst().orElseThrow().split("=",2)[1].trim();
     JSONObject endpoint=NodeChainCaptureHarness.tagged(new JSONObject(original.config).getJSONArray("endpoints"),proof.getJSONObject(0).getString("tag"));
     check(endpoint.getString("type").equals("routervpn-amneziawg")&&endpoint.getJSONObject("amnezia").getString("jc").equals(junkCount),"selected AWG2 packet parameters differ from its captured raw asset");
     for(int i=1;i<total-1;i++)check(proof.getJSONObject(i).getString("kind").equals("public-path")&&source.members.get(i).imported&&original.identityInputs.get(i).isEmpty(),"projected selected AWG2 source changed a public role");
     check(!original.identityInputs.get(total-1).isEmpty()&&!source.members.get(total-1).imported,"selected AWG2 source borrowed its private final");
    }
    check(chosen.plan.extendedOriginalNodeCount()==total,"selected source did not identify the exact original extended owner");
    check(chosen.plan.extendedOriginalStatusLimit()==original.plan.extendedLocalStatusLimit(),"extended selected reply size changed");
    JSONObject prep=new JSONObject(chosen.source);
    check(original.multipleImported&&prep.getInt("schema")==6&&prep.length()==4,"selected source lost its typed registry");
    check(prep.getString("multiple_imported_local_launch").equals(original.launchInput),"selected preparation substituted the original sealed launch");
    check(original.sourceSHA256.equals(chosen.plan.localSourceSHA256())&&chosen.requested.equals(requested),"selected preparation changed the requested execution");
    try(var reopened=AndroidNodeChainExecutionCapture.reopen(original,chosen.launchInput)){
     check(reopened.source.equals(chosen.source)&&reopened.config.equals(chosen.config),"selected execution replay changed original source");
    }
    var altered=new JSONObject(chosen.launchInput);altered.put("source",chosen.source+" ");
    reject(()->{try(var ignored=AndroidNodeChainExecutionCapture.reopen(original,altered.toString())){}},"replayed substituted source");
    reject(()->{try(var ignored=AndroidNodeChainExecutionCapture.fromLast(original,requested,"{}")){}},"unproved Last adopted an imported winner");
   }
   f.change();f.paired.profiles.load(saved.id);
   var restored=f.paired.profiles.currentOrderedPath();
   check(restored.execution.equals(requested)&&restored.modes.equals(source.modes),"profile load lost selected imported execution");
   try(var original=AndroidNodeChainCapture.compile(restored);
       var chosen=AndroidNodeChainExecutionCapture.compile(original,requested)){
    check(original.memberInputs.size()==source.members.size()&&new JSONObject(chosen.source).getInt("schema")==6,"restored selected source omitted a member");
   }
  }
 }
 static void selectedFastBounds(Path root)throws Exception{
  for(String fixture:List.of("3/awg-strong","3/mixed-awg")){
   int paired=3;
   var f=new Fixture(root,fixture,9-paired);var draft=f.draft();f.addAll(draft);
   for(String requested:List.of("server","auto"))reject(()->draft.setExecution(requested),"unqualified extended packet source acquired selected execution");
   check(draft.execution().equals("local")&&draft.save().members.size()==9,"rejected selected source lost its original Local route");
  }
 }
 static void layers(Path root)throws Exception{
  for(String key:List.of("3/aes-256-gcm","4/aes-256-gcm+xor-whitening")){
   var f=new Fixture(root,key,2);var draft=f.draft();f.addAll(draft);var source=draft.save();
   try(var capture=AndroidNodeChainCapture.compile(source)){
    JSONObject launch=new JSONObject(capture.launchInput);check(launch.getInt("schema")==6,"layered final lost independent source family");
    for(int i=0;i<source.members.size();i++)if(!source.members.get(i).imported){JSONObject member=new JSONObject(capture.memberInputs.get(i));check(new JSONObject(member.getString("profile_json")).optString("start_layer","off").equals(source.members.get(i).profile().optString("start_layer","off")),"Local imports changed a paired member Start Layer");}
   }
  }
 }
 static void refusals(Path root)throws Exception{
  var f=new Fixture(root,"3/",2);var draft=f.draft();f.addAll(draft);List<String> before=new ArrayList<>();for(var m:draft.members())before.add(m.source.id);
  reject(()->draft.movePrefix(2,0),"imported member acquired physical first position");
  reject(()->draft.setFinal(f.imports.get(0).id,"shadowsocks"),"imported member became paired final");
  reject(()->draft.addPrefix(f.imports.get(0).id,"shadowsocks"),"duplicate imported identity entered graph");
  for(int i=0;i<before.size();i++)check(draft.members().get(i).source.id.equals(before.get(i)),"rejected edit changed complete order");
  var saved=draft.save();check(AndroidNodeChainCapture.sourceSchema(saved.members,saved.modes)==6,"multiple imports lost schema six");
  for(String protocol:List.of("socks5","http","https")){
   var other=imported(10,"2022-blake3-aes-256-gcm");other.protocol=protocol;other.username="original-user";other.password="original-password";if(protocol.equals("https"))other.tlsServerName="original.example";f.exits.save(other);
   var edit=f.draft();String mode=AndroidExternalPolicy.protocol(protocol);check(!edit.prefixModes(other.id).contains(mode),"typed imported family offered inside schema six");reject(()->edit.addPrefix(other.id,mode),"typed imported member widened schema six");
  }
  var hostname=NodeChainCaptureHarness.hostnameEntry("2022-blake3-aes-256-gcm");hostname.id=String.format("%032x",1020);f.exits.save(hostname);var edit=f.draft();
  check(!edit.prefixModes(hostname.id).contains("shadowsocks"),"hostname offered independent literal authority");reject(()->edit.addPrefix(hostname.id,"shadowsocks"),"schema six acquired hostname DNS authority");
  var legacy=new Fixture(root,"2/",1);var one=legacy.draft();legacy.addAll(one);var single=one.save();verify(legacy,single,2);
 }
 static void rollback(Path root)throws Exception{
  for(String fault:List.of("first-import","second-import","preferences")){
   var f=new Fixture(root,"2/",2);var draft=f.draft();f.addAll(draft);draft.save();var saved=f.paired.profiles.add("Independent rollback");f.change();var before=new NodeChainCaptureHarness.State(f.paired);
   int[] writes={0};if(fault.equals("preferences"))f.paired.prefs.failures=1;
   else{AndroidPrivateFileStore.failPath=new File(f.paired.context.getFilesDir(),"standard-exits.json").getAbsolutePath();AndroidPrivateFileStore.beforeIndependentWrite=file->{if(file.getName().equals("standard-exits.json")&&++writes[0]==(fault.equals("first-import")?1:2))AndroidPrivateFileStore.failures=1;};}
   try{reject(()->f.paired.profiles.load(saved.id),"partial imported profile publication was accepted");before.same(f.paired,"complete imported rollback "+fault);checks++;}
   finally{AndroidPrivateFileStore.beforeIndependentWrite=null;AndroidPrivateFileStore.beforeWrite=null;AndroidPrivateFileStore.failPath="";AndroidPrivateFileStore.failures=0;f.paired.prefs.failures=0;}
  }
 }
 static void stale(Path root)throws Exception{
  for(int at=0;at<2;at++){
   var f=new Fixture(root,"2/",2);var draft=f.draft();f.addAll(draft);var saved=draft.save();var stale=f.draft();
   var old=f.imports.get(at);var changed=f.exits.get(old.id);changed.secret=Base64.getEncoder().encodeToString(new byte[old.method.contains("128")?16:32]);f.exits.save(changed);f.exits.save(old);
   reject(saved::requireCurrent,"changed-away-and-back imported source revived capture");reject(stale::save,"changed-away-and-back imported source revived editor");
  }
 }
 static void sourceRace(Path root)throws Exception{
  var f=new Fixture(root,"2/",2);var draft=f.draft();f.addAll(draft);draft.save();var saved=f.paired.profiles.add("Exact imported compare-and-save");f.change();
  var newer=f.exits.get(f.imports.get(0).id);newer.name="Newer independent editor";newer.secret=Base64.getEncoder().encodeToString(new byte[16]);
  AndroidPrivateFileStore.beforeIndependentWrite=file->{AndroidPrivateFileStore.beforeIndependentWrite=null;try{f.exits.save(newer);}catch(Exception failure){throw new IllegalStateException(failure);}};
  try{reject(()->f.paired.profiles.load(saved.id),"profile transaction overwrote a newer imported source");check(f.exits.get(newer.id).secret.equals(newer.secret)&&f.exits.get(newer.id).name.equals(newer.name),"profile rollback replaced a newer imported owner");}
  finally{AndroidPrivateFileStore.beforeIndependentWrite=null;}
 }
 static void compiler(Path root)throws Exception{
  var f=new Fixture(root,"2/",2);var draft=f.draft();f.addAll(draft);draft.save();var saved=f.paired.profiles.add("Complete compiler before writes");f.change();var before=new NodeChainCaptureHarness.State(f.paired);
  io.nekohasekai.libbox.Libbox.beforeIndependentCompile=()->{throw new IllegalStateException("injected complete native proposal refusal");};
  try{reject(()->f.paired.profiles.load(saved.id),"complete Local compiler refusal was ignored before publication");before.same(f.paired,"complete native refusal before publication");checks++;}
  finally{io.nekohasekai.libbox.Libbox.beforeIndependentCompile=null;}
 }
 // The original preview comes from the real Go compiler. Only its returned
 // launch document is mutated at this explicit JNI boundary; config and hash
 // methods still read that same original native object.
 static void previewReceipts(Path root)throws Exception{
  var f=new Fixture(root,"2/",2);var draft=f.draft();f.addAll(draft);draft.save();
  var saved=f.paired.profiles.add("Sealed complete native preview");f.change();
  f.paired.profiles.load(saved.id);verify(f,f.paired.profiles.currentOrderedPath(),6);
  f.change();var before=new NodeChainCaptureHarness.State(f.paired);
  for(String fault:List.of("source-hash","config-hash","original-config-hash","metadata-format","missing-field","extra-field","substituted-field","metadata-valid")){
   var reads=new java.util.concurrent.atomic.AtomicInteger();
   io.nekohasekai.libbox.RouterNodeChain.independentPreviewReadback=value->{
    try{
     JSONObject changed=new JSONObject(value);if(changed.getInt("schema")!=6)return value;reads.incrementAndGet();
     switch(fault){
      case "source-hash":changed.put("source_sha256",differentHash(changed.getString("source_sha256")));break;
      case "config-hash":changed.put("config_sha256",differentHash(changed.getString("config_sha256")));break;
      case "original-config-hash":changed.put("original_config_sha256",differentHash(changed.getString("original_config_sha256")));break;
      case "metadata-format":changed.put("metadata_sha256","G".repeat(64));break;
      case "missing-field":changed.remove("metadata_sha256");break;
      case "extra-field":changed.put("foreign_native_receipt",true);break;
      case "substituted-field":changed.remove("metadata_sha256");changed.put("foreign_native_receipt",true);break;
      case "metadata-valid":changed.put("metadata_sha256",differentHash(changed.getString("metadata_sha256")));break;
      default:throw new IllegalArgumentException("unknown native preview fault");
     }
     return changed.toString();
    }catch(Exception failure){throw new IllegalStateException(failure);}
   };
   try{
    reject(()->f.paired.profiles.load(saved.id),"native preview receipt drift was accepted: "+fault);
    check(reads.get()>0,"native preview mutation was not reached: "+fault);
    before.same(f.paired,"native preview refusal "+fault);checks++;
   }finally{io.nekohasekai.libbox.RouterNodeChain.independentPreviewReadback=null;}
  }
 }
 static String differentHash(String value){return (value.charAt(0)=='0'?"1":"0")+value.substring(1);}
 // Synthetic completed-response data is an explicit native boundary. The
 // original source/config and each imported position below come from the real
 // complete shared compiler. Native fifty-response proof is a separate gate.
 static JSONObject historyReceipt(AndroidNodeChainCapture capture,AndroidNodeStore.ChainCapture source,int at,String request)throws Exception{
  int count=source.members.size();var member=source.members.get(at);
  JSONObject distribution=new JSONObject().put("samples",50).put("min_ms",1).put("median_ms",2).put("average_ms",2).put("p90_ms",3).put("max_ms",4).put("jitter_ms",1);
  JSONObject benchmark=new JSONObject().put("schema",1).put("measurement",AndroidOrderedLatencyStore.PUBLIC).put("endpoint",AndroidOrderedLatencyStore.ENDPOINT).put("attempts",50).put("failed",0).put("distribution",distribution).put("trimmed_mean_ms",2);
  JSONObject result=new JSONObject().put("node_id",member.profileId).put("role",at==0?"entry":"intermediate").put("kind","public-path").put("label","Cumulative path through custom node "+(at+1)+" of "+count+" → Cloudflare edge").put("ready",true).put("benchmark",benchmark);
  return new JSONObject().put("schema",1).put("source_sha256",capture.sourceSHA256).put("config_sha256",capture.configSHA256).put("generation_sha256","c".repeat(64)).put("position",at).put("node_id",member.profileId).put("request_id",request).put("measured_at",System.currentTimeMillis()).put("result",result);
 }
 static String historyStatus(JSONObject receipt,String request)throws Exception{return new JSONObject().put("request_id",request).put("stage","complete").put("complete",true).put("drained",true).put("results",new JSONArray().put(receipt.getJSONObject("result"))).toString();}
 static void history(Path root)throws Exception{
  for(String shape:List.of("adjacent","separated")){
   var f=new Fixture(root,shape.equals("adjacent")?"2/":"4/mixed-awg",2);var editor=f.draft();f.addAll(editor);if(shape.equals("separated"))editor.movePrefix(3,1);
   var source=editor.save();try(var capture=AndroidNodeChainCapture.compile(source)){
    check(new JSONObject(capture.launchInput).getInt("schema")==6,"history fixture lost complete original imported set");
    int observed=0;for(int at=1;at<source.members.size()-1;at++)if(source.members.get(at).imported){
     final int position=at;String request=String.format("%032x",at+1);JSONObject receipt=historyReceipt(capture,source,at,request);String raw=receipt.toString(),status=historyStatus(receipt,request);String node=source.members.get(at).profileId;
     AndroidOrderedLatencyStore.Record record;try{record=AndroidOrderedLatencyStore.completed(status,raw,request,capture.sourceSHA256,capture.configSHA256,at,node,"public-path");}catch(Exception refusal){throw new AssertionError("earlier imported history was refused",refusal);}
     check(record.position==at&&record.count==source.members.size()&&record.node.equals(node),"history replaced an imported position or original identity");
     AndroidOrderedLatencyStore.save(f.paired.context,record,source::requireCurrent);
     var loaded=AndroidOrderedLatencyStore.load(f.paired.context,capture.sourceSHA256,capture.configSHA256,at,node,"public-path");check(loaded!=null&&loaded.raw.equals(raw),"earlier imported receipt lost durable exact readback");observed++;
     for(String fault:List.of("source","config","request","position","node","49-samples","49-attempts","failed-response")){
      JSONObject changed=new JSONObject(raw);JSONObject benchmark=changed.getJSONObject("result").getJSONObject("benchmark");
      switch(fault){case "source":changed.put("source_sha256","d".repeat(64));break;case "config":changed.put("config_sha256","e".repeat(64));break;case "request":changed.put("request_id","f".repeat(32));break;case "position":changed.put("position",at==1?2:1);break;case "node":changed.put("node_id","another-original-node");changed.getJSONObject("result").put("node_id","another-original-node");break;case "49-samples":benchmark.getJSONObject("distribution").put("samples",49);break;case "49-attempts":benchmark.put("attempts",49);break;case "failed-response":benchmark.put("failed",1);break;}
      reject(()->AndroidOrderedLatencyStore.completed(historyStatus(changed,request),changed.toString(),request,capture.sourceSHA256,capture.configSHA256,position,node,"public-path"),"history accepted substituted or partial original receipt: "+fault);
     }
     for(int bad:new int[]{0,source.members.size()-1}){JSONObject changed=new JSONObject(raw).put("position",bad);changed.getJSONObject("result").put("label","Cumulative path through custom node "+(bad+1)+" of "+source.members.size()+" → Cloudflare edge");reject(()->new AndroidOrderedLatencyStore.Record(changed.toString()),"public history acquired entry/final authority");}
     for(String selected:List.of("local","server")){
      JSONObject selectedReceipt=new JSONObject(raw);selectedReceipt.getJSONObject("result").put("label","Cumulative "+selected+" path through custom node "+(at+1)+" of "+source.members.size()+" → Cloudflare edge");
      if(at==source.members.size()-2)check(new AndroidOrderedLatencyStore.Record(selectedReceipt.toString(),selected).position==at,"existing selected execution middle receipt refused");
      else reject(()->new AndroidOrderedLatencyStore.Record(selectedReceipt.toString(),selected),"Local schema six widened selected Server/Compare history");
     }
    }
    check(observed==2,"history omitted an independently imported position");
    JSONObject stale=historyReceipt(capture,source,1,"9".repeat(32));var record=new AndroidOrderedLatencyStore.Record(stale.toString());var newer=f.exits.get(f.imports.get(0).id);newer.name="Newer imported history source";f.exits.save(newer);
    reject(()->AndroidOrderedLatencyStore.save(f.paired.context,record,source::requireCurrent),"history publication ignored replaced original source");
   }
  }
 }
 static void customEntry(Path root)throws Exception{
  var f=new Fixture(root,"2/",2);var draft=f.draft();draft.removePrefix(0);
  var before=new NodeChainCaptureHarness.State(f.paired);
  check(draft.prefixModes(f.imports.get(0).id).contains("shadowsocks"),"first custom import was omitted");
  draft.addPrefix(f.imports.get(0).id,"shadowsocks");
  reject(draft::save,"incomplete custom entry draft saved");before.same(f.paired,"incomplete custom route");
  reject(()->draft.setExecution("server"),"custom entry draft borrowed Server");
  draft.addPrefix(f.imports.get(1).id,"shadowsocks");
  reject(()->draft.setExecution("auto"),"custom entry acquired Compare");
  var capture=draft.save();verify(f,capture,7);
  var saved=f.paired.profiles.add("Two custom nodes then paired final");
  f.change();f.paired.profiles.load(saved.id);var restored=f.paired.profiles.currentOrderedPath();
  verify(f,restored,7);var selection=f.draft().matchingSavedPath();check(selection!=null&&selection.members.get(0).id.equals(f.imports.get(0).id),"reopened editor lost custom entry");
  var prepared=IndependentLast.prepareOrderedExecution(f.paired.context,restored);
  check(prepared!=null,"original custom-entry Last source was not prepared");
  AndroidHomeStateStore.Snapshot home=AndroidHomeStateStore.current;
  check(!IndependentLast.recordOrderedExecution(f.paired.context,prepared,home),"unproved Home saved Last");
  home.sessionId="d".repeat(32);home.connected=true;home.phase="connected";home.pathProof="passed";home.logicalMode="node-chain";home.runtimeMode="node-chain";
  home.activeNodeId=restored.control.id;home.activeChain=IndependentLast.members(restored);
  check(IndependentLast.recordOrderedExecution(f.paired.context,prepared,home),"proved complete custom-entry Last was not saved");
  check("local".equals(IndependentLast.replay(f.paired.context,restored)),"original custom-entry Last did not reopen");
  home.connected=false;home.phase="off";
  try(var compiled=AndroidNodeChainCapture.compile(restored)){
   synchronized(AndroidHomeStateStore.class){synchronized(AndroidPrivateFileStore.class){
    var history=restored.historyReadback();compiled.requireHistoryCurrent(history);history.close();
    reject(()->compiled.requireHistoryCurrent(history),"retired history source survived");
   }}
   for(int i=0;i<2;i++){
    String request=String.format("%032x",i+1);JSONObject receipt=historyReceipt(compiled,restored,i,request);
    var record=AndroidOrderedLatencyStore.completed(historyStatus(receipt,request),receipt.toString(),request,compiled.sourceSHA256,compiled.configSHA256,i,restored.members.get(i).profileId,"public-path");
    AndroidOrderedLatencyStore.save(f.paired.context,record,restored::requireCurrent);
    check(AndroidOrderedLatencyStore.load(f.paired.context,compiled.sourceSHA256,compiled.configSHA256,i,restored.members.get(i).profileId,"public-path").position==i,"custom benchmark saved to wrong position");
   }
   var changed=f.exits.get(f.imports.get(0).id);changed.expectedPublicIp="203.0.113.249";f.exits.save(changed);
   reject(()->IndependentLast.replay(f.paired.context,f.paired.profiles.currentOrderedPath()),"Last reused a changed custom entry");
   synchronized(AndroidHomeStateStore.class){synchronized(AndroidPrivateFileStore.class){
    reject(restored::historyReadback,"changed original custom entry revived Last/history");
   }}
  }
 }
 public static void main(String[] args)throws Exception{
  Path root=Path.of(args[0]);String phase=args[1];
  switch(phase){case "hostname-four":mixedHostname(root,4);break;case "hostname-nine":mixedHostname(root,9);break;case "hostname-sixteen":mixedHostname(root,16);break;case "selected-fast-nine":selectedExecution(root,9,"2/awg-fast");break;case "selected-fast-sixteen":selectedExecution(root,16,"2/awg-fast");break;case "selected-strong-nine":selectedExecution(root,9,"2/awg-strong");break;case "selected-strong-sixteen":selectedExecution(root,16,"2/awg-strong");break;case "selected-fast-bounds":selectedFastBounds(root);break;case "selected-execution":selectedExecution(root,0,"3/aes-256-gcm");break;case "selected-extended-nine":selectedExecution(root,9,"2/");break;case "selected-extended-sixteen":selectedExecution(root,16,"2/");break;case "custom-entry":customEntry(root);break;case "extended-nine":case "extended-sixteen":roundtrip(root,phase);mixedExtended(root,phase.equals("extended-nine")?9:16);if(phase.equals("extended-sixteen"))mixedLatePacket(root);break;case "adjacent":case "separated":case "single-interior":case "maximum":case "awg-fast":case "awg-strong":roundtrip(root,phase);break;case "layers":layers(root);break;case "refusals":refusals(root);break;case "rollback":rollback(root);break;case "stale":stale(root);break;case "source-race":sourceRace(root);break;case "compiler":compiler(root);break;case "preview-receipts":previewReceipts(root);break;case "history":history(root);break;default:throw new IllegalArgumentException("unknown complete imported Local phase");}
  System.out.println("Android independent imported Local "+phase+": "+checks+" checks PASS");
 }
}
'''


def prepare_last(app, java):
    # Keep the shipping Last transaction intact. Home/Android disk are the
    # ordinary fixture boundaries. Server execution cannot enter this Local test.
    from test_android_connection_profiles import method
    source = (java / "AndroidStartupPolicy.java").read_text()
    first = source.index("    static final class OrderedLast {")
    last = source.index("    /** Complete source identity", first)
    functions = source[first:last]
    for name in ("profileIdentity", "canonical", "selectionPreferences", "prefs"):
        start = next(line.strip().split("(")[0]+"(" for line in source.splitlines()
                     if line.strip().startswith("private static ") and (" "+name+"(") in line)
        functions += method("AndroidStartupPolicy.java", start)+"\n"
    (app / "IndependentLast.java").write_text(
        "package com.eabusham.routervpn; import android.content.*; import java.io.*; import org.json.*; "
        "import java.util.*; import java.security.*; import java.nio.charset.StandardCharsets; "
        "final class IndependentLast {static final int MAX_LAST=4096,MAX_ORDERED_LAST=40*1024;"
        'static final String PREFS="router-vpn-unified",ORDERED_LAST_FILE="startup-ordered-last-v1.json";'
        +functions+"static String members(AndroidNodeStore.ChainCapture s)throws Exception{return orderedMembers(s);}"
        + "static String replay(Context c,AndroidNodeStore.ChainCapture s)throws Exception{return requireLastOrdered(c,s).selected;}}")
    shutil.copyfile(java / "AndroidNodeChainExecutionCapture.java", app / "AndroidNodeChainExecutionCapture.java")
    shutil.copyfile(java / "AndroidMTUMeasurementGate.java", app / "AndroidMTUMeasurementGate.java")


def prepare_sources(src, app, java):
    BASE.prepare_sources(src, app, java)
    shutil.copyfile(java / "AndroidOrderedLatencyStore.java", app / "AndroidOrderedLatencyStore.java")
    (app / "MultipleImportedLocalHarness.java").write_text(HARNESS)
    prepare_last(app, java)
    # Explicit native-boundary mutation: retain actual Go config/hash reads from
    # the original constructor input while corrupting only launchInput readback.
    native = src / "io/nekohasekai/libbox/RouterNodeChain.java"
    source = native.read_text()
    launch = 'public String launchInput()throws Exception{if(closed)throw new IllegalStateException("retired pure compiler handle");return input;}'
    replacement = 'public static java.util.function.UnaryOperator<String> independentPreviewReadback;\n public String launchInput()throws Exception{if(closed)throw new IllegalStateException("retired pure compiler handle");var hook=independentPreviewReadback;return hook==null?input:hook.apply(input);}'
    assert source.count(launch) == 1
    source = source.replace(launch, replacement)
    for before, after in (
        ('Libbox.call("chain-config",launchInput())', 'Libbox.call("chain-config",originalInput())'),
        ('new org.json.JSONObject(launchInput())', 'new org.json.JSONObject(originalInput())'),
    ):
        assert before in source
        source = source.replace(before, after)
    closing = 'public void close(){closed=true;}'
    assert source.count(closing) == 1
    source = source.replace(closing, 'private String originalInput()throws Exception{if(closed)throw new IllegalStateException("retired pure compiler handle");return input;}\n ' + closing)
    native.write_text(source)
    boundaries = app / "Boundaries.java"
    storage = boundaries.read_text()
    before_hook = "Runnable hook=beforeWrite;if(hook!=null)hook.run();"
    assert storage.count(before_hook) == 1
    storage = storage.replace('String phase="off";', 'String phase="off",sessionId="",pathProof="",logicalMode="",runtimeMode="",activeNodeId="",activeChain="",activeEntryId="",activeExitId="",activeExternalId="";long pathGeneration;')
    storage = storage.replace("final class AndroidHomeStateStore {", "final class AndroidHomeStateStore {static boolean emergencyDisconnectPending(android.content.Context context){return false;}")
    storage = storage.replace("final class AndroidPrivateFileStore {", "final class AndroidPrivateFileStore {\n static java.util.function.Consumer<File> beforeIndependentWrite;")
    storage = storage.replace(before_hook, before_hook + "java.util.function.Consumer<File> independent=beforeIndependentWrite;if(independent!=null)independent.accept(file);")
    boundaries.write_text(storage)
    libbox = src / "io/nekohasekai/libbox/Libbox.java"
    source = libbox.read_text()
    before = 'public static RouterNodeChain newRouterNodeChain(String source)throws Exception{return new RouterNodeChain(call("chain-new",source));}'
    after = 'public static Runnable beforeIndependentCompile;\npublic static RouterNodeChain newRouterNodeChain(String source)throws Exception{if(new org.json.JSONObject(source).getInt("schema")==6&&beforeIndependentCompile!=null)beforeIndependentCompile.run();return new RouterNodeChain(call("chain-new",source));}'
    assert source.count(before) == 1
    source = source.replace(before, after)
    source = source[:-1] + 'public static String routerIndependentProofs(String source)throws Exception{return call("chain-independent-proofs",source);}public static String routerIndependentCandidateMetric(String source,int pos)throws Exception{return call("independent-candidate-metric",source,Integer.toString(pos));}}'
    libbox.write_text(source)


def phase(command, name, env):
    result = subprocess.run([*command, name], env=env, text=True, capture_output=True, timeout=180)
    expected = re.findall(r"^Android independent imported Local " + re.escape(name) + r": ([1-9][0-9]*) checks PASS$", result.stdout, re.M)
    if result.returncode != 0 or len(expected) != 1:
        raise AssertionError("complete imported Local phase failed: " + name + "\n" + result.stdout + result.stderr)
    print(result.stdout, end="", flush=True)
    return int(expected[0])


def run(root, work, app, classes, jar, env, imported_only=False):
    if imported_only:
        raise ValueError("independent imports require their complete Local inventory")
    generator = work / "android_chain_fixture_test.go"
    generator.write_text(BASE.GENERATOR)
    overlay = work / "independent-fixture-overlay.json"
    overlay.write_text(json.dumps({"Replace": {str(root / "internal/mobilemultihop/android_chain_fixture_test.go"): str(generator)}}))
    env = env.copy()
    env["ROUTERVPN_ANDROID_CHAIN_FIXTURE"] = str(work / "private-chain-fixtures.json")
    subprocess.run(["go", "test", "-p=1", "-count=1", "-overlay=" + str(overlay), "./internal/mobilemultihop", "-run", "^TestAndroidOrderedSourceFixture$"], cwd=root, env=env, check=True, timeout=180)
    data = work / "independent-data"
    data.mkdir()
    command = ["java", "-Xmx768m", "-cp", str(classes) + os.pathsep + str(jar), "com.eabusham.routervpn.MultipleImportedLocalHarness", str(data)]
    counts = [phase(command, name, env) for name in PHASES]
    print("Android independent imported Local inventory: " + str(len(PHASES)) + " phases, " + str(sum(counts)) + " checks PASS", flush=True)
    controls = (
        ("schema", "AndroidNodeChainCapture", "        return 6;", '        throw new IllegalStateException("old single-import boundary");', "adjacent", "complete independent Local source was refused"),
        ("hostname-candidate", "AndroidNodeChainCapture", "if (schema==2 && i==prefix || schema==6 && AndroidStandardExitStore.importedHostname(source.external()))", "if (schema==2 && i==prefix)", "hostname-four", "mixed hostname candidate omitted original stream"),
        ("selected-fast-mode", "AndroidNodeChainCapture", '!List.of("wg","awg2-fast","awg2-strong").contains(modes.get(0))', '!"wg".equals(modes.get(0))', "selected-fast-nine", "The longer mixed packet and stream route requires Local execution."),
        ("selected-strong-mode", "AndroidNodeChainCapture", '!List.of("wg","awg2-fast","awg2-strong").contains(modes.get(0))', '!List.of("wg","awg2-fast").contains(modes.get(0))', "selected-strong-nine", "The longer mixed packet and stream route requires Local execution."),
        ("first-policy", "AndroidConnectionProfileStore", "                exits.saveIfUnchanged(update.updated,AndroidStandardExitStore.snapshot(update.original));", "                if(appliedImports.size()>1)exits.saveIfUnchanged(update.updated,AndroidStandardExitStore.snapshot(update.original));", "adjacent", "profile Load lost an earlier imported policy"),
        ("rollback", "AndroidConnectionProfileStore", "for(int i=appliedImports.size()-1;i>=0;i--)", "for(int i=appliedImports.size()-1;i>0;i--)", "rollback", "lost exact file rollback"),
        ("complete-preview", "AndroidConnectionProfileStore", "if(schema==6 || schema==7)AndroidNodeChainCapture.validateLocalImportedSources(sources,modes);", "if(false)AndroidNodeChainCapture.validateLocalImportedSources(sources,modes);", "compiler", "complete Local compiler refusal was ignored before publication"),
        ("preview-seal", "AndroidNodeChainCapture", "RouterNodeChain sealed=Libbox.routerNodeChainLaunch(launch);", "RouterNodeChain sealed=preview;", "preview-receipts", "native preview receipt drift was accepted: metadata-valid"),
        ("history-middle", "AndroidOrderedLatencyStore", "(!selectedExecution.isEmpty()&&!multipleImported&&position!=count-2)", "position!=count-2", "history", "earlier imported history was refused"),
    )
    for name, owner, before, after, selected, witness in controls:
        source = (app / (owner + ".java")).read_text()
        if source.count(before) != 1:
            raise AssertionError("independent imported control anchor changed: " + name)
        changed = work / ("independent-mutant-" + name) / (owner + ".java")
        changed.parent.mkdir()
        changed.write_text(source.replace(before, after))
        output = work / ("independent-negative-" + name)
        shutil.copytree(classes, output)
        cp = str(output) + os.pathsep + str(jar)
        subprocess.run(["javac", "--release", "17", "-encoding", "UTF-8", "-proc:none", "-cp", cp, "-d", str(output), str(changed)], check=True, timeout=60)
        result = subprocess.run(["java", "-Xmx768m", "-cp", cp, command[4], str(data), selected], env=env, text=True, capture_output=True, timeout=180)
        if result.returncode != 1 or witness not in result.stderr or any(x in result.stderr for x in ("OutOfMemoryError", "StackOverflowError", "ExceptionInInitializerError", "NoClassDefFoundError")):
            raise AssertionError("independent imported control missed its intended witness: " + name + "\n" + result.stdout + result.stderr)
        print("Android independent imported Local causal control PASS: " + name, flush=True)


if __name__ == "__main__":
    import test_android_connection_profiles as profiles
    if len(sys.argv) != 1:
        raise ValueError("This gate takes no arguments")
    sys.argv += ["--case-family", "ordered-multiple-imported"]
    profiles.main()
