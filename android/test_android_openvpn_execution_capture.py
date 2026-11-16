#!/usr/bin/env python3
"""Exercise typed OpenVPN execution with real shared source compilation.

The shipping stores/editor/capture retain the complete sealed Local launch.
Native forwarding, provider establishment, Last capture and restoration are
separate boundaries; a pure source compilation cannot establish any of them.
"""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import test_android_node_chain_execution_capture as BASE


def compiler_source(source):
    result = BASE.compiler_source(source)
    anchor = 'case len(args)==2:'
    if result.count(anchor) != 1:
        raise AssertionError('Actual source fixture command dispatch changed')
    case = 'case len(args)==2&&args[0]=="openvpn-local-metadata":var original *mobilemultihop.NodeChain;original,err=mobilemultihop.ParseNodeChainLaunchInput(args[1]);if err==nil{result=original.Metadata()};'
    return result.replace(anchor, case + anchor)


HARNESS = r'''package com.eabusham.routervpn;
import org.json.*;import java.nio.file.*;import java.util.*;import io.nekohasekai.libbox.*;
public final class OpenVPNExecutionCaptureHarness {
 static int checks;interface Checked{void run()throws Exception;}static void check(boolean ok,String why){checks++;if(!ok)throw new AssertionError(why);}
 static void reject(Checked operation,String why)throws Exception{try{operation.run();}catch(Exception expected){checks++;return;}throw new AssertionError(why);}
 static AndroidStandardExitStore.Entry provider(String network)throws Exception{
  var e=new AndroidStandardExitStore.Entry();e.id="1234567890abcdef1234567890abcdef";e.name="Original OpenVPN provider";e.protocol="openvpn";
  e.server="203.0.113.20";e.serverPort=1194;e.expectedPublicIp="203.0.113.88";e.username=" exact provider user ";e.password=" exact provider secret ";
  JSONObject paired=new JSONObject(Files.readString(Path.of(System.getenv("ROUTERVPN_ANDROID_CHAIN_FIXTURE")))).getJSONObject("openvpn/provider/"+network),profile=paired.getJSONObject("profile");
  e.openVPNConfig=profile.getString("config");e.username=profile.getString("username");e.password=profile.getString("password");e.openVPNPairing=new JSONObject(paired.getJSONObject("pairing").toString());
  e.policy.put("dns_mode","rescue").put("start_layer","off").put("home_lan_access",false).put("kill_switch_policy","always");return e;
 }
 static NodeChainCaptureHarness.Fixture fixture(Path root,int count,String layer)throws Exception {
  var f=new NodeChainCaptureHarness.Fixture(root,(count-1)+"/"+(count==3?"awg-strong":"mixed-awg"));
  JSONObject finalBundle=f.bundle(count-2);NodeChainCaptureHarness.profile(finalBundle).put("start_layer",layer);f.replace(count-2,finalBundle);return f;
 }
 static AndroidNodeChainCapture selected(NodeChainCaptureHarness.Fixture f,AndroidStandardExitStore.Entry provider,String requested)throws Exception {
  var exits=new AndroidStandardExitStore(f.context);exits.save(provider);var editor=new AndroidOrderedPathSelection(f.nodes,f.profiles);
  check(editor.prefixModes(provider.id).equals(List.of("openvpn"))&&AndroidOrderedPathSelection.prefixModeTitle("openvpn").equals("Custom OpenVPN"),"OpenVPN editor lost its original provider mode");
  editor.addPrefix(provider.id,"openvpn");editor.save();var ui=new OrderedProductSurface(f);ui.open();ui.choose(0);ui.execution();
  check(ui.dialog.labels.length==3&&ui.dialog.labels[2].toString().equals("Compare both"),"OpenVPN public editor lost complete execution choices");
  ui.choose(requested.equals("server")?1:2);check(ui.dialog!=null&&ui.message.isEmpty(),"OpenVPN editor refused typed execution");ui.save();
  check(ui.message.isEmpty(),"OpenVPN public Save refused typed execution");var saved=f.profiles.currentOrderedPath();
  check(saved.execution.equals(requested)&&saved.members.get(saved.members.size()-2).imported,"OpenVPN Save replaced the original provider position");
  return AndroidNodeChainCapture.compile(saved);
 }
 static void originalSource(AndroidNodeChainCapture local,AndroidNodeChainExecutionCapture execution,AndroidStandardExitStore.Entry provider,int count,String layer)throws Exception {
  check(local.openVPN&&local.plan!=null&&local.socks==null&&local.connect==null,"OpenVPN execution lost its original generic Local owner");
  JSONObject prep=new JSONObject(execution.source),source=new JSONObject(prep.getString("local_source")),launch=new JSONObject(local.launchInput);
  check(prep.length()==4&&prep.getInt("schema")==5&&prep.getString("openvpn_local_launch").equals(local.launchInput),"OpenVPN preparation lost exact sealed Local authority");
  check(source.length()==4&&source.getInt("schema")==5&&source.getString("execution").equals("local")&&new JSONObject(execution.launchInput).getString("kind").equals("routervpn-node-chain-openvpn-execution-preparation-input"),"OpenVPN execution borrowed another source family");
  check(source.getJSONArray("nodes").length()==count&&source.getJSONArray("identity_sources").length()==count,"OpenVPN execution shortened original inventory");
  JSONArray proofs=new JSONObject(OpenVPNSourceFixture.metadata(local.launchInput)).getJSONArray("proofs");check(proofs.length()==count,"OpenVPN source omitted original proof inventory");
  for(int i=0;i<count;i++){
   check(source.getJSONArray("nodes").getString(i).equals(local.memberInputs.get(i))&&source.getJSONArray("identity_sources").getString(i).equals(local.identityInputs.get(i))&&launch.getJSONArray("nodes").getString(i).equals(local.memberInputs.get(i))&&local.identityInputs.get(i).isEmpty()==(i==count-2),"OpenVPN execution changed an original member or private identity");
   JSONObject proof=proofs.getJSONObject(i),member=new JSONObject(local.memberInputs.get(i));check(proof.getInt("position")==i,"OpenVPN source renumbered an original proof");
   if(i==count-2)check(proof.getString("node_id").isEmpty()&&proof.getString("node_kind").equals("external")&&proof.getString("mode").equals("openvpn"),"OpenVPN provider borrowed a private Router proof");
   else{JSONObject profile=new JSONObject(member.getString("profile_json"));String selectedLayer=profile.optString("start_layer","off");if(selectedLayer.isEmpty())selectedLayer="off";
    check(proof.getString("node_id").equals(profile.getString("node_proof_id"))&&proof.getString("profile_id").equals(profile.getString("id"))&&proof.getString("mode").equals(member.getString("mode"))&&proof.getString("start_layer").equals(selectedLayer),"OpenVPN proof replaced original paired identity, mode or layer");}
  }
  JSONObject member=new JSONObject(local.memberInputs.get(count-2)),original=new JSONObject(member.getString("capture")).getJSONObject("profile").getJSONObject("external").getJSONObject("openvpn");
  check(member.getString("kind").equals("routervpn-node-chain-openvpn-member")&&original.getString("config").equals(provider.openVPNConfig)&&original.getString("username").equals(provider.username)&&original.getString("password").equals(provider.password),"OpenVPN execution changed exact provider config or credentials");
  JSONObject external=new JSONObject(member.getString("capture")).getJSONObject("profile").getJSONObject("external");
  check(ConnectionProfilesHarness.sameJSONValue(external.getJSONObject("openvpn_pairing"),provider.openVPNPairing),"OpenVPN execution replaced original independent provider pairing");
  JSONObject graph=new JSONObject(local.config),projected=new JSONObject(execution.config);String middleTag=proofs.getJSONObject(count-2).getString("tag"),finalTag=proofs.getJSONObject(count-1).getString("tag");
  JSONObject middle=NodeChainCaptureHarness.tagged(graph.getJSONArray("endpoints"),middleTag),last=NodeChainCaptureHarness.tagged(graph.getJSONArray("outbounds"),finalTag);
  check(middle.getString("type").equals("openvpn-client")&&middle.getString("detour").equals(proofs.getJSONObject(count-3).getString("tag"))&&last.getString("detour").equals(middleTag),"OpenVPN source changed original packet predecessor or final detour");
  check(ConnectionProfilesHarness.sameJSONValue(middle,NodeChainCaptureHarness.tagged(projected.getJSONArray("endpoints"),middleTag))&&ConnectionProfilesHarness.sameJSONValue(last,NodeChainCaptureHarness.tagged(projected.getJSONArray("outbounds"),finalTag)),"OpenVPN preparation replaced original provider or final transport");
  check(!last.has("udp_over_tcp")&&last.getString("type").equals(layer.equals("aes-256-gcm+xor-whitening")?"routervpn-aes-xor":"shadowsocks")&&proofs.getJSONObject(count-1).getString("start_layer").equals(layer),"OpenVPN execution lost independent final Start Layer");
  check(local.strict&&!local.homeLANAccess,"OpenVPN source dropped aggregate original policy");
 }
 static void positive(Path root,int count,String network,String layer)throws Exception {
  for(String requested:List.of("server","auto")){
   var f=fixture(root,count,layer);var provider=provider(network);
   try(var local=selected(f,provider,requested);var execution=AndroidNodeChainExecutionCapture.compile(local,requested)){
    originalSource(local,execution,provider,count,layer);
    try(var replay=AndroidNodeChainExecutionCapture.reopen(local,execution.launchInput)){check(replay.source.equals(execution.source)&&replay.config.equals(execution.config),"OpenVPN execution replay changed exact original preparation");}
    reject(()->Libbox.routerNodeChainExecutionFromLaunch(local.launchInput,requested),"generic execution accepted OpenVPN authority");
    reject(()->Libbox.newRouterNodeChainExecutionLaunch(execution.launchInput),"generic launch accepted OpenVPN execution");
    reject(()->Libbox.newRouterNodeChainSOCKSExecutionLaunch(execution.launchInput),"SOCKS launch accepted OpenVPN execution");
    reject(()->Libbox.newRouterNodeChainCONNECTExecutionLaunch(execution.launchInput),"CONNECT launch accepted OpenVPN execution");
    check(!execution.healthy(),"OpenVPN source fabricated native proof");reject(execution::captureRestore,"OpenVPN source fabricated native restore");
   }
  }
 }
 static void profiles(Path root,int count,String network)throws Exception {
  var f=fixture(root,count,"aes-256-gcm+xor-whitening");var provider=provider(network);var exits=new AndroidStandardExitStore(f.context);
  try(var local=selected(f,provider,"auto");var execution=AndroidNodeChainExecutionCapture.compile(local,"auto")){
   var row=f.profiles.add("Original layered OpenVPN execution");String record=Files.readString(f.rows);
   check(!record.contains(provider.password)&&!record.contains("peer-fingerprint")&&!record.contains(provider.openVPNPairing.getString("private_key"))&&!record.contains("openvpn_pairing"),"OpenVPN profile duplicated provider credentials");
   f.profiles.load(row.id);var loaded=f.profiles.currentOrderedPath();check(loaded.members.size()==count&&loaded.execution.equals("auto")&&loaded.members.get(count-2).external().openVPNConfig.equals(provider.openVPNConfig),"OpenVPN profile Load changed original provider or execution");
   try(var current=AndroidNodeChainCapture.compile(loaded);var prepared=AndroidNodeChainExecutionCapture.compile(current,"auto")){check(prepared.source.equals(execution.source),"OpenVPN saved profile changed complete source");}
   provider.password="replacement provider secret";exits.save(provider);reject(execution::requireCurrent,"OpenVPN execution survived provider credential replacement");
   var update=new AndroidOrderedPathSelection(f.nodes,f.profiles);update.setExecution("server");update.save();f.profiles.update(row.id,"Updated original provider");f.changePolicies();f.profiles.load(row.id);
   var updated=f.profiles.currentOrderedPath();check(updated.execution.equals("server")&&updated.members.size()==count&&updated.members.get(count-2).external().password.equals(provider.password)&&updated.members.get(count-1).profile().getString("start_layer").equals("aes-256-gcm+xor-whitening"),"OpenVPN profile Update lost original source references or final layer");
   try(var current=AndroidNodeChainCapture.compile(updated);var prepared=AndroidNodeChainExecutionCapture.compile(current,"server")){
    JSONObject replacement=f.bundle(count-3);NodeChainCaptureHarness.profile(replacement).put("api_token","replacement-prefix-token");f.replace(count-3,replacement);reject(prepared::requireCurrent,"OpenVPN execution survived original prefix replacement");
   }
   f.profiles.delete(row.id);check(f.members.stream().allMatch(n->n.file.isFile()),"OpenVPN profile Delete removed private node files");
  }
 }
 static void unpairedRefusal(Path root)throws Exception {
  var f=fixture(root,3,"off");var provider=provider("udp");provider.openVPNPairing=null;
  var exits=new AndroidStandardExitStore(f.context);exits.save(provider);var localDraft=new AndroidOrderedPathSelection(f.nodes,f.profiles);localDraft.addPrefix(provider.id,"openvpn");var saved=localDraft.save();
  try(var local=AndroidNodeChainCapture.compile(saved)){check(local.openVPN&&local.selectionExecution.equals("local"),"Unpaired OpenVPN lost its existing Local source");}
  for(String requested:List.of("server","auto")){
   var draft=new AndroidOrderedPathSelection(f.nodes,f.profiles);draft.setExecution(requested);var before=new NodeChainCaptureHarness.State(f);
   reject(draft::save,"OpenVPN remote execution borrowed unpaired provider authority");before.same(f,"Unpaired OpenVPN preview refusal");
  }
 }
 static void readback(Path root,int count)throws Exception {
  if(count==3)unpairedRefusal(root);
  var f=fixture(root,count,"aes-256-gcm");var provider=provider("udp");
  try(var local=selected(f,provider,"server")){
   for(String fault:List.of("schema","extra","seal","missing-seal","member","identity","middle-identity","position","config","requested")){
    Libbox.afterExecution=p->{try{
     if(fault.equals("config")){p.value.put("config_sha256","f".repeat(64));return;}if(fault.equals("requested")){p.value.put("requested","auto");return;}
     JSONObject prep=new JSONObject(p.value.getString("source")),source=new JSONObject(prep.getString("local_source"));
     if(fault.equals("schema"))prep.put("schema",1);else if(fault.equals("extra"))prep.put("foreign_owner","foreign");else if(fault.equals("seal"))prep.put("openvpn_local_launch",new JSONObject(local.launchInput).put("metadata_sha256","f".repeat(64)).toString());else if(fault.equals("missing-seal"))prep.remove("openvpn_local_launch");
     else{JSONArray rows=source.getJSONArray(fault.contains("identity")?"identity_sources":"nodes");int position=fault.equals("middle-identity")?count-2:fault.equals("position")?count-1:count-3;rows.put(position,rows.getString(position==0?1:0));prep.put("local_source",source.toString());}
     p.value.put("source",prep.toString());JSONObject launch=new JSONObject(p.value.getString("launch"));launch.put("source",prep.toString());p.value.put("launch",launch.toString());
    }catch(Exception error){throw new IllegalStateException(error);}};
    try{reject(()->AndroidNodeChainExecutionCapture.compile(local,"server"),"OpenVPN accepted changed readback: "+fault);}finally{Libbox.afterExecution=null;}
   }
   reject(()->Libbox.routerNodeChainOpenVPNExecutionFromLaunch(local.sourceInput,"server"),"OpenVPN accepted stripped raw Local source");
   for(String field:List.of("source_sha256","config_sha256","metadata_sha256","original_config_sha256")){
    String altered=new JSONObject(local.launchInput).put(field,"f".repeat(64)).toString();reject(()->Libbox.routerNodeChainOpenVPNExecutionFromLaunch(altered,"server"),"OpenVPN accepted changed sealed Local "+field);
   }
   for(String choice:List.of("local","Server","compare",""," auto"))reject(()->Libbox.routerNodeChainOpenVPNExecutionFromLaunch(local.launchInput,choice),"OpenVPN normalized an unowned execution choice");
   var draft=new AndroidOrderedPathSelection(f.nodes,f.profiles);draft.setExecution("auto");var before=new NodeChainCaptureHarness.State(f);final boolean[] reached={false};
   Libbox.afterExecution=p->{reached[0]=true;throw new IllegalStateException("controlled OpenVPN preview refusal");};
   try{reject(draft::save,"OpenVPN Save bypassed typed preview refusal");check(reached[0],"OpenVPN Save never reached typed preview");before.same(f,"OpenVPN preview refusal");}finally{Libbox.afterExecution=null;}
  }
 }
 public static void main(String[] args)throws Exception {
  Path root=Path.of(args[0]);String phase=args[1];String[] parts=phase.split("/");
  if(parts[0].equals("positive"))positive(root,Integer.parseInt(parts[1]),parts[2],parts[3]);
  else if(parts[0].equals("profiles"))profiles(root,Integer.parseInt(parts[1]),parts[2]);
  else if(parts[0].equals("readback"))readback(root,Integer.parseInt(parts[1]));else throw new AssertionError("Unknown complete OpenVPN phase");
  System.out.println("Android typed OpenVPN execution: "+checks+" actual compiler/store checks PASS");
 }
}
'''


def prepare_sources(src, app, java):
    BASE.prepare_sources(src, app, java)
    (app / 'OpenVPNExecutionCaptureHarness.java').write_text(HARNESS)
    (src / 'io/nekohasekai/libbox/OpenVPNSourceFixture.java').write_text('package io.nekohasekai.libbox;public final class OpenVPNSourceFixture{public static String metadata(String input)throws Exception{return Libbox.call("openvpn-local-metadata",input);}}')



def fixture_generator():
    original = BASE.LOCAL.GENERATOR; anchor = '{4,"mixed-awg"},{8,"mixed-awg"}'
    if original.count(anchor) != 1:
        raise AssertionError('Complete mixed packet fixture inventory changed')
    original = original.replace(anchor, '{4,"mixed-awg"},{5,"mixed-awg"},{6,"mixed-awg"},{8,"mixed-awg"}')
    original = original.replace('"router-vpn/internal/nativecomposite";', '"router-vpn/internal/nativecomposite";"router-vpn/internal/nativeopenvpn";', 1)
    anchor = ' raw,err:=json.Marshal(result);if err!=nil{t.Fatal(err)}'
    if original.count(anchor) != 1:
        raise AssertionError('Original fixture publication changed')
    # Explicit configured packet capacity belongs to these new positive source
    # fixtures. The production envelope guards and original fixture stay intact.
    prepare = r''' for key,value:=range result{
  if strings.HasPrefix(key,"connect/"){continue}
  for position,item:=range value.([]any){
   bundles:=value.([]any);if position==len(bundles)-1{continue};bundle:=item.(map[string]any);assets:=bundle["profiles"].(map[string]any)
   for _,mode:=range []string{"wg","awg2-fast","awg2-strong"}{files,ok:=assets[mode].(map[string]string);if !ok{continue};for _,name:=range []string{"wg.conf","awg.conf"}{if raw,ok:=files[name];ok{decoded,err:=base64.StdEncoding.Strict().DecodeString(raw);if err!=nil{t.Fatal(err)};files[name]=base64.StdEncoding.EncodeToString([]byte(strings.ReplaceAll(string(decoded),"MTU = 2000","MTU = 4096")))}}}
  }
 }
 for _,network:=range []string{"tcp","udp"}{
  profile:=nativeopenvpn.Profile{Config:"client\ndev tun\nproto "+network+"\nremote 203.0.113.20 1194\nauth-user-pass\nremote-cert-tls server\npeer-fingerprint "+strings.Repeat("ab",32)+"\ntun-mtu 1400\ndata-ciphers AES-256-GCM:AES-128-GCM\n",Username:" exact provider user ",Password:" exact provider secret "}
  server:=profile;server.Username="independent-server-provider";server.Password="independent-server-private-secret"
  localKey:=base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{71},32));serverKey:=base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{72},32))
  localPublic,err:=nativeopenvpn.DescribePeer(profile,localKey);if err!=nil{t.Fatal(err)};serverPublic,err:=nativeopenvpn.DescribePeer(server,serverKey);if err!=nil{t.Fatal(err)}
  if err=nativeopenvpn.ValidatePublicPair(localPublic,serverPublic);err!=nil{t.Fatal(err)}
  result["openvpn/provider/"+network]=map[string]any{"profile":profile,"pairing":nativeopenvpn.Pairing{PrivateKey:localKey,Server:serverPublic},"server_profile":server,"server_key":serverKey,"local_public":localPublic,"server_public":serverPublic}
 }
'''
    return original.replace(anchor, prepare + anchor)


def run(root, work, app, classes, jar, env, imported_only=False):
    generator = work / 'android_chain_fixture_test.go'
    generator.write_text(fixture_generator())
    overlay = work / 'openvpn-fixture-overlay.json'
    overlay.write_text(json.dumps({'Replace': {str(root / 'internal/mobilemultihop/android_chain_fixture_test.go'): str(generator)}}))
    env = env.copy(); env['ROUTERVPN_ANDROID_CHAIN_FIXTURE'] = str(work / 'private-chain-fixtures.json')
    subprocess.run(['go', 'test', '-p=1', '-count=1', '-overlay=' + str(overlay), './internal/mobilemultihop', '-run', '^TestAndroidOrderedSourceFixture$'], cwd=root, env=env, check=True, timeout=180)
    data = work / 'openvpn-data'; data.mkdir(); cp = os.pathsep.join((str(classes), str(jar)))
    command = ['java', '-cp', cp, 'com.eabusham.routervpn.OpenVPNExecutionCaptureHarness', str(data)]
    phases = [f'positive/{count}/{network}/off' for count in range(3, 9) for network in ('tcp', 'udp')]
    phases += [f'positive/{count}/{"tcp" if count % 2 else "udp"}/{layer}' for count in range(3, 9) for layer in ('aes-256-gcm', 'aes-256-gcm+xor-whitening')]
    phases += [f'profiles/{count}/{network}' for count, network in ((3, 'tcp'), (8, 'udp'))]
    phases += ['readback/3', 'readback/8']
    for phase in phases:
        subprocess.run([*command, phase], env=env, check=True, timeout=120)
    controls = (
        ('generic-preview', 'AndroidNodeChainCapture', 'Libbox.routerNodeChainOpenVPNExecutionFromLaunch(local.launchInput(),execution)', 'Libbox.routerNodeChainExecutionFromLaunch(local.launchInput(),execution)', 'positive/3/tcp/off', 'OpenVPN public Save refused typed execution'),
        ('missing-sealed-readback', 'AndroidNodeChainExecutionCapture', 'local.openVPN && !local.launchInput.equals(preparation.getString("openvpn_local_launch"))', 'false', 'readback/3', 'OpenVPN accepted changed readback: seal'),
        ('missing-member-readback', 'AndroidNodeChainExecutionCapture', '!sameStrings(original.getJSONArray("nodes"), returned.getJSONArray("nodes"))', 'false', 'readback/8', 'OpenVPN accepted changed readback: member'),
        ('missing-identity-readback', 'AndroidNodeChainExecutionCapture', '!sameStrings(original.getJSONArray("identity_sources"), returned.getJSONArray("identity_sources"))', 'false', 'readback/8', 'OpenVPN accepted changed readback: identity'),
    )
    for name, owner, before, after, phase, witness in controls:
        captured = (app / (owner + '.java')).read_text()
        if captured.count(before) != 1:
            raise AssertionError('OpenVPN causal source boundary changed: ' + name)
        target = work / ('openvpn-mutant-' + name) / (owner + '.java'); target.parent.mkdir(); target.write_text(captured.replace(before, after))
        output = work / ('openvpn-negative-' + name); shutil.copytree(classes, output); classpath = os.pathsep.join((str(output), str(jar)))
        subprocess.run(['javac', '--release', '17', '-encoding', 'UTF-8', '-proc:none', '-cp', classpath, '-d', str(output), str(target)], check=True, timeout=60)
        result = subprocess.run(['java', '-cp', classpath, command[3], str(data), phase], env=env, text=True, capture_output=True, timeout=120)
        if result.returncode != 1 or witness not in result.stderr or 'java.lang.AssertionError' not in result.stderr:
            raise AssertionError(name + ' missed intended OpenVPN witness:\n' + result.stdout + result.stderr)
        print('OpenVPN source causal refusal: ' + name, flush=True)


if __name__ == '__main__':
    import test_android_connection_profiles as profiles
    if len(sys.argv) != 1:
        raise ValueError('This gate takes no arguments')
    sys.argv += ['--case-family', 'ordered-openvpn-execution']
    profiles.main()
