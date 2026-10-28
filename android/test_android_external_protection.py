#!/usr/bin/env python3
"""Execute saved/captured Android protection and reject weakened native decisions.

Uses the production Java policy helper and Android's actual org.json library.
OS booleans are supplied at the same boundary used by LayeredVpnService; the
separate whole-service tests exercise that caller with Android handles doubled.
"""
from pathlib import Path
import os
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
JAVA = ROOT / "android/app/src/main/java/com/eabusham/routervpn"
HARNESS = r'''package com.eabusham.routervpn;
import org.json.*;
public class ProtectionTest {
 static int checks;interface Attempt{void run()throws Exception;}
 static void check(boolean ok,String label){checks++;if(!ok)throw new AssertionError(label);}
 static void reject(Attempt action,String label)throws Exception{checks++;try{action.run();}catch(Exception expected){return;}throw new AssertionError(label);}
 static JSONObject profile(String setting)throws Exception{
  JSONObject p=new JSONObject().put("id","exit-owned");if(!setting.equals("legacy"))p=AndroidExternalProtection.withChoice(p,setting.equals("on"));return p;
 }
 static JSONObject entry(boolean required)throws Exception{return new JSONObject().put("id","entry-owned").put("kill_switch",required).put("kill_switch_policy",required?"always":"off");}
 static JSONObject ordinary(String setting,String protocol)throws Exception{return profile(setting).put("id","entry-owned").put("node_kind","external").put("external",new JSONObject().put("protocol",protocol).put("expected_public_ip","203.0.113.9"));}
 static JSONObject capture(JSONObject profile,JSONObject entry)throws Exception{JSONObject c=new JSONObject().put("exit_id","exit-owned").put("profile",profile);if(entry!=null)c.put("entry",entry);return c;}
 static JSONObject tor(JSONObject profile,JSONObject entry)throws Exception{JSONObject c=new JSONObject().put("external_id","exit-owned").put("tor_profile",profile);if(entry!=null)c.put("predecessor_profile",entry);return c;}
 public static void main(String[] args)throws Exception{
  for(String setting:new String[]{"legacy","off","on"})for(int predecessor=0;predecessor<3;predecessor++){
   JSONObject p=profile(setting),e=predecessor==0?null:entry(predecessor==2);
   boolean explicit=setting.equals("on"),legacy=setting.equals("legacy"),required=explicit||legacy&&predecessor==0||predecessor==2;
   check(AndroidExternalProtection.externalCapture(capture(p,e))==required,"ordinary exit borrowed or discarded protection owner");
   boolean torRequired=explicit||legacy||predecessor==2;
   check(AndroidExternalProtection.torCapture(tor(p,e))==torRequired,"Tor discarded legacy or explicit captured protection");
  }
  for(String protocol:new String[]{"wireguard","amneziawg","socks5","http-connect","https-connect","shadowsocks","hysteria2","openvpn"})for(String entrySetting:new String[]{"legacy","off","on"})for(String exitSetting:new String[]{"legacy","off","on"}){
   JSONObject e=ordinary(entrySetting,protocol),p=profile(exitSetting),metadata=tor(p,e);String before=metadata.toString();boolean predecessor=!entrySetting.equals("off"),required=predecessor||!exitSetting.equals("off");
   check(AndroidExternalProtection.entryRequested(e)==predecessor,"ordinary predecessor lost its direct legacy or explicit choice");
   check(AndroidExternalProtection.torCapture(metadata)==required,"Tor exit removed independent ordinary protection: "+protocol+"/"+entrySetting+"/"+exitSetting);
   check(AndroidExternalProtection.externalCapture(capture(p,e))==(predecessor||exitSetting.equals("on")),"ordinary predecessor changed the selected via-entry exit default");
   check(before.equals(metadata.toString()),"protection evaluation mutated captured ordinary source");
   AndroidExternalProtection.requireSession(required,required,29,true,true);
   if(required){reject(()->AndroidExternalProtection.requireSession(false,required,29,true,true),"ordinary protection accepted missing marker");reject(()->AndroidExternalProtection.requireSession(true,required,29,true,false),"ordinary protection accepted absent Android lockdown");}
   else AndroidExternalProtection.requireSession(false,false,28,false,false);
  }
  for(boolean typed:new boolean[]{false,true})for(String entrySetting:new String[]{"legacy","off","on"})for(String exitSetting:new String[]{"legacy","off","on"}){
   JSONObject e=profile(entrySetting).put("id","entry-owned");if(typed)e.put("node_kind","router-vpn");
   check(AndroidExternalProtection.entryRequested(e)==entrySetting.equals("on"),"ordinary default leaked into a legacy/private Router predecessor");
   check(AndroidExternalProtection.torCapture(tor(profile(exitSetting),e))==(entrySetting.equals("on")||!exitSetting.equals("off")),"private Router and Tor policy matrix changed");
  }
  for(String value:new String[]{"off","on-connect","always","strict","lockdown","on","enabled"," ALWAYS "}){
   JSONObject e=ordinary("legacy","socks5").put("kill_switch_policy",value);check(AndroidExternalProtection.entryRequested(e)!=value.equals("off"),"ordinary requested policy differs from direct/UI semantics");
   JSONObject privateEntry=new JSONObject().put("node_kind","router-vpn").put("kill_switch_policy",value);
   boolean strict=java.util.Arrays.asList("always","strict","lockdown").contains(value.trim().toLowerCase(java.util.Locale.US));check(AndroidExternalProtection.entryRequested(privateEntry)==strict,"private Router strict policy was widened by ordinary support");
  }
  check(!AndroidExternalProtection.entryRequested(ordinary("legacy","socks5").put("kill_switch",false)),"explicit ordinary Boolean Off inherited strict default");
  for(Object bad:new Object[]{true,1,JSONObject.NULL,new JSONObject(),"ordinary",""," EXTERNAL "})reject(()->AndroidExternalProtection.torCapture(tor(profile("on"),entry(false).put("node_kind",bad))),"malformed predecessor kind accepted");
  for(Object bad:new Object[]{JSONObject.NULL,new JSONObject(),"socks5",1,true})reject(()->AndroidExternalProtection.torCapture(tor(profile("on"),ordinary("legacy","socks5").put("external",bad))),"ordinary kind lost its transport descriptor");
  for(Object bad:new Object[]{"http","https","tor","tor-bridge","unknown","",1,true,JSONObject.NULL,new JSONObject()})reject(()->AndroidExternalProtection.torCapture(tor(profile("on"),ordinary("off","socks5").put("external",new JSONObject().put("protocol",bad)))),"ordinary kind accepted a noncanonical/unsupported protocol");
  reject(()->AndroidExternalProtection.entryRequested(new JSONObject().put("node_kind","external")),"ordinary kind accepted a missing descriptor");
  reject(()->AndroidExternalProtection.torCapture(tor(profile("on"),ordinary("legacy","socks5").put("kill_switch","false"))),"strong Tor exit skipped malformed ordinary protection");
  for(String value:new String[]{"off","on-connect","always","strict","lockdown","on","enabled"," ALWAYS "}){
   check(AndroidExternalProtection.requested(new JSONObject().put("kill_switch_policy",value),false)!=value.equals("off"),"saved protection policy lost");
  }
  JSONObject source=new JSONObject().put("id","exit-owned").put("password","private-fixture").put("dns_mode","home").put("manual_mtu",1380).put("bootstrap",new JSONObject().put("private","owner"));
  String before=source.toString();JSONObject changed=AndroidExternalProtection.withChoice(source,false);
  check(!changed.getBoolean("kill_switch")&&changed.getString("kill_switch_policy").equals("off"),"Off did not persist explicitly");
  changed.remove("kill_switch");changed.remove("kill_switch_policy");check(before.equals(changed.toString()),"protection edited unrelated private policy");
  changed.getJSONObject("bootstrap").put("private","other");check(before.equals(source.toString()),"protection aliased its captured source");
  for(Object bad:new Object[]{"false",1,JSONObject.NULL,new JSONObject()})reject(()->AndroidExternalProtection.requested(new JSONObject().put("kill_switch",bad),false),"malformed protection Boolean accepted");
  for(Object bad:new Object[]{"",true,1,"disabled",JSONObject.NULL,new JSONObject()})reject(()->AndroidExternalProtection.requested(new JSONObject().put("kill_switch_policy",bad),false),"malformed protection policy accepted");
  reject(()->AndroidExternalProtection.externalCapture(capture(profile("on").put("id","wrong"),null)),"wrong external owner accepted");
  reject(()->AndroidExternalProtection.torCapture(tor(profile("on").put("id","wrong"),null)),"wrong Tor owner accepted");
  reject(()->AndroidExternalProtection.externalCapture(capture(profile("on"),entry(false).put("kill_switch","true"))),"strong exit skipped malformed independent entry");
  for(boolean required:new boolean[]{false,true})for(boolean marker:new boolean[]{false,true})for(int sdk:new int[]{28,29,36})for(boolean always:new boolean[]{false,true})for(boolean lockdown:new boolean[]{false,true}){
   boolean valid=required==marker&&(!required||sdk>=29&&always&&lockdown);
   try{AndroidExternalProtection.requireSession(marker,required,sdk,always,lockdown);check(valid,"missing OS or marker proof accepted");}
   catch(IllegalStateException failure){check(!valid,"explicit Off or complete lockdown proof rejected");}
  }
  System.out.println("Android captured external protection: "+checks+" checks passed");
 }
}
'''


def main():
    jar = Path(os.environ.get("ANDROID_JSON_JAR", "/usr/share/java/com.android.json.jar"))
    if not jar.is_file() or not shutil.which("javac"):
        raise RuntimeError("JDK and Android JSON are required for captured protection tests")
    source = (JAVA / "AndroidExternalProtection.java").read_text(encoding="utf-8")
    mutations = (
        ("legacy default", "return legacyDefault;", "return false;"),
        ("entry ownership", "return selected || predecessor;", "return selected;"),
        ("ordinary predecessor legacy default", "return requested(entry, true);", "return requested(entry, false);"),
        ("ordinary explicit Off", "return requested(entry, true);", "return true;"),
        ("ordinary transport identity", 'if (!Arrays.asList("wireguard", "amneziawg", "socks5", "http-connect", "https-connect", "shadowsocks", "hysteria2", "openvpn").contains(protocol))', "if (false)"),
        ("unexpected inherited direct default", "requested(profile, entry == null)", "requested(profile, true)"),
        ("explicit Off", '.put("kill_switch_policy", enabled ? "always" : "off")', '.put("kill_switch_policy", "always")'),
        ("saved Boolean type", 'if (policy.has("kill_switch") && !(policy.get("kill_switch") instanceof Boolean))', 'if (false)'),
        ("exit identity", 'if (!capture.getString("exit_id").equals(profile.getString("id")))', 'if (false)'),
        ("Tor identity", 'if (!metadata.getString("external_id").equals(profile.getString("id")))', 'if (false)'),
        ("marker binding", "if (marker != required)", "if (false)"),
        ("native lockdown", "if (required && (sdk < 29 || !alwaysOn || !lockdown))", "if (false)"),
    )
    with tempfile.TemporaryDirectory(prefix="routervpn-android-protection-") as directory:
        temp = Path(directory)
        helper = temp / "AndroidExternalProtection.java"
        harness = temp / "ProtectionTest.java"
        harness.write_text(HARNESS, encoding="utf-8")
        classes = temp / "classes"
        compile_args = ["javac", "--release", "17", "-encoding", "UTF-8", "-cp", str(jar), "-d", str(classes), str(helper), str(harness)]
        run_args = ["java", "-cp", os.pathsep.join((str(classes), str(jar))), "com.eabusham.routervpn.ProtectionTest"]
        helper.write_text(source, encoding="utf-8")
        subprocess.run(compile_args, check=True, timeout=45)
        subprocess.run(run_args, check=True, timeout=20)
        for label, before, after in mutations:
            if before not in source:
                raise AssertionError("Missing production mutation boundary: " + label)
            helper.write_text(source.replace(before, after), encoding="utf-8")
            subprocess.run(compile_args, check=True, timeout=45)
            result = subprocess.run(run_args, capture_output=True, text=True, timeout=20)
            if result.returncode == 0 or "AssertionError" not in result.stderr:
                raise AssertionError("Protection regression escaped: " + label + "\n" + result.stderr)
        print("Android captured protection: 12 broken native/policy decisions rejected")


if __name__ == "__main__":
    main()
