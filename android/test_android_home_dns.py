#!/usr/bin/env python3
"""Execute shipping Home editor methods and native graphs using real Go policy.

Android UI/store/service handles are boundaries; no device or DNS traffic is claimed.
"""
from pathlib import Path
import importlib.util
import os
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('home_graph',ROOT/'android/test_android_multihop_graph.py')
T=importlib.util.module_from_spec(spec);spec.loader.exec_module(T)

def method(source,signature):
    start=source.index(signature);brace=source.index('{',start);depth=1;end=brace+1
    while depth:
        if source[end]=='{':depth+=1
        elif source[end]=='}':depth-=1
        end+=1
    return source[start:end]

editor=(T.JAVA/'AndroidProductParity.java').read_text()
T.STUBS['com/eabusham/routervpn/HomeEditor.java']='''package com.eabusham.routervpn;
import org.json.*;import java.util.*;import java.nio.charset.StandardCharsets;
final class HomeEditor {
 static JSONObject selectedProfile(JSONObject b){return AndroidProfileSelection.selectedRouterProfile(b);}
 static String inferServerName(String h){return h;}
 static void save(AndroidNodeStore store,JSONObject b,String proto,String host,int port,String tls,String path)throws Exception{applyDNS(store,b,"home",proto,host,port,tls,path);}
'''+method(editor,'private static void applyDNS(')+'\n'+method(editor,'static void selectQuickDNS(')+'\n'+method(editor,'static void requireDNSOwner(')+'\n'+method(editor,'private static int parsePort(')+'\nstatic int port(String text){return parsePort(text);}}'
T.STUBS['com/eabusham/routervpn/Boundaries.java']=T.STUBS['com/eabusham/routervpn/Boundaries.java'].replace('final class AndroidNodeStore {','final class AndroidNodeStore {\n static String active="owned-node";String activeId(){return active;}static int writes;static byte[] saved;void importBundle(byte[] b){writes++;saved=b.clone();}')
HOME=r'''
 interface HomeAction{void run()throws Exception;}
 static void homeRejected(HomeAction action)throws Exception{boolean failed=false;try{action.run();}catch(Exception expected){failed=true;}check(failed,"invalid Home policy admitted");}
 static void homeDNS(JSONObject graph,String type,String host)throws Exception{
  JSONObject dns=graph.getJSONObject("dns").getJSONArray("servers").getJSONObject(0);
  check(dns.getString("type").equals(type),"Home transport silently replaced");
  check(dns.getString("server").equals(host)&&dns.getInt("server_port")==5443,"Home address/family/custom port replaced");
  check(dns.getString("detour").equals("proxy"),"Home DNS lost owned tunnel detour");
  if(!type.equals("udp")&&!type.equals("tcp"))check(dns.getJSONObject("tls").getString("server_name").equals("dns.home.example"),"Home TLS identity replaced");
  if(type.equals("https")||type.equals("h3"))check(dns.getString("path").equals("/private-dns%2Fquery"),"Home path replaced");
 }
 public static void main(String[] args)throws Exception{
  Path dir=Path.of(args[0]);
  for(String host:new String[]{"192.168.50.133","fd12::53"})for(String type:new String[]{"udp","tcp","tls","https","h3"})for(String mode:new String[]{"wg","awg2-fast","awg2-strong"}){
   Path app=Files.createTempDirectory(dir,"app-");Context context=new Context(app.toFile());NativeSingBoxController nativeController=new NativeSingBoxController(context);AndroidMultihopController builder=new AndroidMultihopController(context,nativeController);
   JSONObject b=awgBundle('b'),p=profile(b);p.put("adguard_ipv6","fd12::53").put("ipv6_mode","on").put("mtu_policy","fixed").put("manual_mtu",1360);
   String secrets=b.getJSONObject("profiles").toString();
   HomeEditor.save(new AndroidNodeStore(),b,type,host,5443,"dns.home.example","/private-dns%2Fquery");
   b=new JSONObject(new String(AndroidNodeStore.saved,StandardCharsets.UTF_8));p=profile(b);
   check(p.getString("dns_protocol").equals(type)&&p.getString("dns_host").equals(host)&&p.getInt("dns_port")==5443,"settings save replaced explicit Home selection");
   String saved=p.toString();HomeEditor.selectQuickDNS(p,"home");check(saved.equals(p.toString()),"quick Home selection erased saved policy");
   check(secrets.equals(b.getJSONObject("profiles").toString()),"DNS save changed transport credentials");
   check(AndroidNativeProfilePolicy.requiresLibbox(b),"address-only backend admitted nonstandard Home DNS port");
   final JSONObject raw=b;homeRejected(()->AndroidNativeProfilePolicy.patchWireGuardLikeConfig(raw,wg('b'),1380));
   File source=save(dir,b);NativeSingBoxController.SessionInfo session=nativeController.prepareSession(source,mode);
   JSONObject graph=new JSONObject(Files.readString(app.resolve("layered-sessions").resolve(session.sessionId).resolve("sing-box.json")));homeDNS(graph,type,host);
   if(mode.equals("wg"))homeDNS(prepare(builder,app,save(dir,bundle('a')),source,"local"),type,host);
  }
  JSONObject sameLabel=new JSONObject().put("id","same-profile-label");HomeEditor.requireDNSOwner(new AndroidNodeStore(),"owned-node","same-profile-label",sameLabel);AndroidNodeStore.active="different-node";homeRejected(()->HomeEditor.requireDNSOwner(new AndroidNodeStore(),"owned-node","same-profile-label",sameLabel));AndroidNodeStore.active="owned-node";
  check(HomeEditor.port("")==0&&HomeEditor.port("5443")==5443,"DNS form default/explicit port changed");for(String bad:new String[]{"abcd","-1","65536","99999999999999999999","53.5"})homeRejected(()->HomeEditor.port(bad));
  JSONObject defaults=bundle('b');JSONObject p=profile(defaults);p.put("mtu_policy","fixed").put("manual_mtu",1380);
  check(!AndroidNativeProfilePolicy.requiresLibbox(defaults),"default UDP53 Home lost address-only eligibility");
  HomeEditor.selectQuickDNS(p,"home");check(p.getString("dns_protocol").equals("udp")&&p.getInt("dns_port")==53&&p.getString("dns_host").equals("192.168.50.133"),"Home default changed");
  p.put("dns_mode","doh").put("dns_host","1.1.1.1").put("dns_protocol","https").put("dns_port",443).put("dns_server_name","cloudflare-dns.com");HomeEditor.selectQuickDNS(p,"home");check(p.getString("dns_host").equals("192.168.50.133")&&p.getInt("dns_port")==53&&p.getString("dns_server_name").isEmpty(),"entering Home reused foreign public DNS");
  for(String fault:new String[]{"public","foreign","ipv6-off","bad-protocol","bad-port","bad-name","unicode-path","query-path","foreign-path","bad-percent","noncanonical","wrong-type"}){
   JSONObject b=bundle('b'),q=profile(b);q.put("adguard_ipv6","fd12::53").put("dns_protocol","https").put("dns_host","fd12::53").put("dns_port",5443).put("dns_server_name","dns.home.example").put("dns_path","/private-dns");
   switch(fault){case "public":q.put("dns_host","1.1.1.1");break;case "foreign":q.put("dns_host","fd13::53");break;case "ipv6-off":q.put("ipv6_mode","off");break;case "bad-protocol":q.put("dns_protocol","rescue");break;case "bad-port":q.put("dns_port",65536);break;case "bad-name":q.put("dns_server_name","fd12::53");break;case "unicode-path":q.put("dns_path","/café");break;case "query-path":q.put("dns_path","/dns?other=1");break;case "foreign-path":q.put("dns_path","//other.example/dns");break;case "bad-percent":q.put("dns_path","/%zz");break;case "noncanonical":q.put("dns_host","fd12:0::53");break;case "wrong-type":q.put("dns_port","5443");break;}
   String before=q.toString();homeRejected(()->HomeEditor.selectQuickDNS(q,"home"));check(before.equals(q.toString()),"failed Home selection mutated policy");
   homeRejected(()->NativeSingBoxController.applySelectedDns(b,new JSONObject().put("outbounds",new JSONArray().put(new JSONObject().put("tag","proxy").put("type","shadowsocks")))));
  }
  JSONObject fast=bundle('b');profile(fast).put("dns_mode","fastest").put("fastest_dns_host","9.9.9.9").put("dns_protocol","https").put("dns_port",5443);
  JSONObject g=new JSONObject().put("outbounds",new JSONArray().put(new JSONObject().put("tag","proxy").put("type","shadowsocks")));NativeSingBoxController.applySelectedDns(fast,g);
  JSONObject dns=g.getJSONObject("dns").getJSONArray("servers").getJSONObject(0);check(dns.getString("type").equals("udp")&&dns.getInt("server_port")==53&&dns.getString("server").equals("9.9.9.9"),"Fastest measurement semantics changed");
  System.out.println("Android Home settings/native graph: "+checks+" checks passed (actual Go compiler; Android handles doubled)");
 }
}
'''
T.HARNESS=T.HARNESS[:T.HARNESS.index(' public static void main(String[] args)')]+HOME
def main():
    mutant=sys.argv[1] if len(sys.argv)>1 else ''
    if mutant not in ('','--mutant-save','--mutant-native'):
        raise ValueError('unknown Home causal control')
    if mutant=='--mutant-save':
        source=T.STUBS['com/eabusham/routervpn/HomeEditor.java']
        begin=source.index('if("home".equals(mode)){')
        end=source.index('\n        else if("fastest"',begin)
        T.STUBS['com/eabusham/routervpn/HomeEditor.java']=source[:begin]+'if("home".equals(mode)){host=profile.optString("adguard_ipv4",profile.optString("adguard_ipv6",""));protocol="udp";port=53;serverName="";path="";}'+source[end:]
    if mutant=='--mutant-native':
        original=T.shutil.copyfile
        def copy(source,target,*args,**kwargs):
            result=original(source,target,*args,**kwargs)
            if Path(source).name=='NativeSingBoxController.java':
                path=Path(target);text=path.read_text();begin=text.index('if ("home".equals(s.mode)) {');end=text.index('\n        else if ("fastest"',begin)
                path.write_text(text[:begin]+'if ("home".equals(s.mode)) { s.host=firstNonEmpty(profile.optString("adguard_ipv4", ""), profile.optString("adguard_ipv6", "")); s.protocol="udp";s.port=53;s.serverName="";s.path=""; }'+text[end:])
            return result
        T.shutil.copyfile=copy
    T.main()
    if not mutant:
        for control,witness in [('--mutant-save','settings save replaced explicit Home selection'),('--mutant-native','Home address/family/custom port replaced')]:
            result=subprocess.run([sys.executable,__file__,control],cwd=ROOT,capture_output=True,text=True,timeout=180)
            if result.returncode==0 or witness not in result.stderr:
                raise AssertionError('Home original substitution causal control missed '+control+'\n'+result.stdout+result.stderr)
            print('Android Home original substitution causal control rejected: '+control)

if __name__=='__main__':main()
