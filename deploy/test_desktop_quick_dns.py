#!/usr/bin/env python3
"""Verify the actual compact DNS payloads retain captured ownership and encrypted Home."""
from __future__ import annotations
import argparse
from pathlib import Path
import subprocess
import tempfile
from test_desktop_startup_settings import ROOT, read, run, section, windows_adapter_import
from test_desktop_protection_settings import load_transform

PS_TEST = r'''
$ErrorActionPreference='Stop'
$captured=[pscustomobject]@{profile_id='node "quoted"';profile_token='source-revision';mode='home';protocol='https';host='192.168.50.133';port=8443;server_name='home.example';path='/private-query';password='never-copy'}
foreach($mode in @('home','rescue')){
 $body=New-RouterVPNQuickDNSPayload -Captured $captured -DisplayedProfileID 'node "quoted"' -Mode $mode
 if($body.profile_id -cne $captured.profile_id -or $body.profile_token -cne 'source-revision' -or $body.ContainsKey('password')){throw 'Lost captured owner or copied secrets'}
 if($mode -eq 'home'){
  if($body.Count-ne8-or$body.protocol-cne'https'-or$body.host-cne'192.168.50.133'-or$body.port-ne8443-or$body.server_name-cne'home.example'-or$body.path-cne'/private-query'){throw 'Encrypted Home was reset'}
 }elseif($body.Count-ne4-or$body.mode-cne'rescue'-or$body.port-ne0){throw 'Unrelated fields carried into named preset'}
}
$captured.mode='doh'
$body=New-RouterVPNQuickDNSPayload -Captured $captured -DisplayedProfileID 'node "quoted"' -Mode 'home'
if($body.Count-ne4-or$body.ContainsKey('host')-or$body.port-ne0){throw 'Other resolver carried into Home'}
foreach($mode in @('fastest','custom','dot','doh','doh3','unknown')){
 $caught=$false;try{New-RouterVPNQuickDNSPayload -Captured $captured -DisplayedProfileID 'node "quoted"' -Mode $mode}catch{$caught=$true}
 if(-not$caught){throw 'Unmeasured/configuration choice bypassed details'}
}
foreach($displayed in @('','replacement','NODE "quoted"')){
 $caught=$false;try{New-RouterVPNQuickDNSPayload -Captured $captured -DisplayedProfileID $displayed -Mode 'rescue'}catch{$caught=$true}
 if(-not$caught){throw 'Replacement selection accepted'}
}
$RouterCombo=[pscustomobject]@{SelectedValue='node "quoted"'}
$script:reply=$captured;$script:posts=0;$script:change=$false
function Api {
 param([string]$Path,[string]$Method='GET',$Body,[int]$Timeout)
 if($Path-cne'/api/dns/policy'){throw 'Unexpected DNS route'}
 if($Method-eq'GET'){return $script:reply}
 $script:posts++;$script:posted=$Body
}
SetUnifiedDNSPreset -Mode 'rescue'
if($script:posts-ne1-or$script:posted.profile_id-cne'node "quoted"'-or$script:posted.profile_token-cne'source-revision'){throw 'Actual callback lost source'}
$script:reply=[pscustomobject]@{profile_id='replacement';profile_token='new-source';mode='home'}
$caught=$false;try{SetUnifiedDNSPreset -Mode 'rescue'}catch{$caught=$true}
if(-not$caught-or$script:posts-ne1){throw 'Actual callback adopted a changed GET owner'}
'''

def windows(directory,shell):
    product=section(read("client/RouterVPN-Windows-Product-v2.ps1"),r"^function New-RouterVPNDNSPolicyPayload \{.*?^\}")
    source=read("client/RouterVPN-Windows-UnifiedShell.ps1")
    helper=section(source,r"^function New-RouterVPNQuickDNSPayload \{.*?^\}")
    callback=section(source,r"^function SetUnifiedDNSPreset \{.*?^\}")
    assert callback.index("$DisplayedProfileID=")<callback.index("$Captured=Api")
    assert "SetUnifiedDNSPreset -Mode $Tag" in source
    assert "@('fastest','custom','dot','doh','doh3')" in source
    composed=directory/"shipping-composition.ps1"
    composed.write_text(r'''
param([string]$Helper,[string]$Product,[string]$Unified)
$ErrorActionPreference='Stop'
. $Helper
$product=Convert-RouterVPNWindowsProductSessionMutation -Source ([IO.File]::ReadAllText($Product))
$unified=Convert-RouterVPNWindowsUnifiedSessionMutation -Source ([IO.File]::ReadAllText($Unified))
. ([ScriptBlock]::Create($unified))
$composed=Add-RouterVPNUnifiedWindowsShell -ProductSource $product
if(-not$composed.Contains("Assert-RouterVPNMutationIdle 'saving DNS policy'")){throw 'Full DNS editor lost its idle guard'}
if(-not$composed.Contains('SetUnifiedDNSPreset -Mode $Tag')){throw 'Compact DNS handler is not composed'}
$tokens=$null;$parseErrors=$null
[void][System.Management.Automation.Language.Parser]::ParseInput($composed,[ref]$tokens,[ref]$parseErrors)
if($parseErrors.Count){throw ($parseErrors.Message -join '; ')}
''',encoding="utf-8-sig")
    run([shell,"-NoProfile","-ExecutionPolicy","Bypass","-File",str(composed),
         "-Helper",str(ROOT/"client/RouterVPN-Windows-SessionMutation.ps1"),
         "-Product",str(ROOT/"client/RouterVPN-Windows-Product-v2.ps1"),
         "-Unified",str(ROOT/"client/RouterVPN-Windows-UnifiedShell.ps1")])
    variants={"shipping":helper,
              "reset-home":helper.replace("$Mode -eq 'home' -and [string]$Captured.mode -ceq 'home'","$false"),
              "carry-other-resolver":helper.replace("$Mode -eq 'home' -and [string]$Captured.mode -ceq 'home'","$Mode -eq 'home'"),
              "replace-owner":helper.replace("-DisplayedProfileID $DisplayedProfileID","-DisplayedProfileID ([string]$Captured.profile_id)")}
    for name,body in variants.items():
        assert name=="shipping" or body!=helper
        path=directory/(name+".ps1")
        path.write_text(windows_adapter_import()+product+"\n"+body+"\n"+callback+"\n"+PS_TEST,encoding="utf-8-sig")
        run([shell,"-NoProfile","-ExecutionPolicy","Bypass","-File",str(path)],broken=name!="shipping")

SWIFT_TEST=r'''
func check(_ value: Bool,_ message: String){if !value{fatalError(message)}}
var captured:[String:Any]=["profile_id":"node \"quoted\"","profile_token":"source-revision","mode":"home","protocol":"https","host":"192.168.50.133","port":8443,"server_name":"home.example","path":"/private-query","password":"never-copy"]
let home=try productQuickDNSBody(captured:captured,displayedProfileID:"node \"quoted\"",mode:"home")
check(home.count==8 && home["password"]==nil,"private/unrelated fields copied")
check(home["profile_id"] as? String=="node \"quoted\"" && home["profile_token"] as? String=="source-revision","lost owner")
check(home["protocol"] as? String=="https" && home["host"] as? String=="192.168.50.133" && home["port"] as? Int==8443 && home["server_name"] as? String=="home.example" && home["path"] as? String=="/private-query","encrypted Home reset")
for mode in ["home","rescue"]{
 if mode=="home"{captured["mode"]="doh"}
 let body=try productQuickDNSBody(captured:captured,displayedProfileID:"node \"quoted\"",mode:mode)
 check(body.count==4 && body["host"]==nil && body["port"] as? Int==0,"unrelated resolver carried into named preset")
}
for mode in ["fastest","custom","dot","doh","doh3","unknown"]{
 var rejected=false;do{_=try productQuickDNSBody(captured:captured,displayedProfileID:"node \"quoted\"",mode:mode)}catch{rejected=true}
 check(rejected,"unmeasured or configurable choice bypassed details")
}
for displayed in ["","replacement","NODE \"quoted\""]{
 var rejected=false;do{_=try productQuickDNSBody(captured:captured,displayedProfileID:displayed,mode:"rescue")}catch{rejected=true}
 check(rejected,"replacement owner accepted")
}
'''

def macos(directory):
    product=section(read("client/macos/RouterVPNMacProduct.swift"),r"^func productDNSPolicyBody\(.*?^\}")
    source=read("client/macos/RouterVPNMacUnifiedShell.swift")
    helper=section(source,r"^func productQuickDNSBody\(.*?^\}")
    transform=load_transform("mac_quick_dns_transform","client/macos/macos-session-mutation-transform.py")
    full_editor=transform.transform(read("client/macos/RouterVPNMacProduct.swift"),"product")
    editor_save=section(full_editor,r"^    @objc func saveDNS\(.*?^    \}")
    assert 'guard ensureMutationIdle("saving DNS policy")' in editor_save
    assert 'asyncAction { try self.requireMutationIdle("saving DNS policy")' in editor_save
    shipping=transform.transform(source,"unified")
    callback=section(shipping,r"^    @objc func unifiedDNSChanged\(.*?^    \}")
    assert callback.index("let displayedProfileID =")<callback.index("asyncAction")
    assert 'self.requireMutationIdle("changing DNS policy")' in callback
    assert 'productQuickDNSBody(captured: captured, displayedProfileID: displayedProfileID, mode: mode)' in callback
    assert '["fastest", "custom", "dot", "doh", "doh3"].contains(mode) { openUnifiedDNS(); return }' in callback
    variants={"shipping":helper,
              "reset-home":helper.replace('mode == "home", captured?["mode"] as? String == "home"',"false"),
              "carry-other-resolver":helper.replace('mode == "home", captured?["mode"] as? String == "home"','mode == "home"'),
              "replace-owner":helper.replace("displayedProfileID: displayedProfileID",'displayedProfileID: captured?["profile_id"] as? String ?? ""')}
    for name,body in variants.items():
        assert name=="shipping" or body!=helper
        path,binary=directory/(name+".swift"),directory/name
        path.write_text("import Foundation\n"+product+"\n"+body+"\n"+SWIFT_TEST,encoding="utf-8")
        run(["swiftc","-swift-version","6","-module-cache-path",str(directory/"swift-module-cache"),str(path),"-o",str(binary)])
        run([str(binary)],broken=name!="shipping")

C_TEST=r'''
static void check(gboolean v,const char *m){if(!v){g_printerr("%s\n",m);exit(1);}}
int main(void){
 JsonObject *capture=json_object_new();
 json_object_set_string_member(capture,"profile_id","node \"quoted\"");
 json_object_set_string_member(capture,"profile_token","source-revision");
 json_object_set_string_member(capture,"mode","home");
 json_object_set_string_member(capture,"protocol","https");
 json_object_set_string_member(capture,"host","192.168.50.133");
 json_object_set_int_member(capture,"port",8443);
 json_object_set_string_member(capture,"server_name","home.example");
 json_object_set_string_member(capture,"path","/private-query");
 json_object_set_string_member(capture,"password","never-copy");
 const char *modes[]={"home","rescue","home"};
 for(guint i=0;i<G_N_ELEMENTS(modes);i++){
  if(i==2)json_object_set_string_member(capture,"mode","doh");
  char *body=linux_quick_dns_payload_v22(capture,"node \"quoted\"",modes[i]);
  check(body!=NULL,"payload missing");
  JsonParser *p=json_parser_new();check(json_parser_load_from_data(p,body,-1,NULL),"invalid JSON");
  JsonObject *o=json_node_get_object(json_parser_get_root(p));
  check(json_object_get_size(o)==8 && !json_object_has_member(o,"password"),"private/unrelated fields copied");
  check(strcmp(obj_string(o,"profile_id"),"node \"quoted\"")==0 && strcmp(obj_string(o,"profile_token"),"source-revision")==0,"lost source");
  if(i==0){check(strcmp(obj_string(o,"protocol"),"https")==0 && strcmp(obj_string(o,"host"),"192.168.50.133")==0 && json_object_get_int_member(o,"port")==8443 && strcmp(obj_string(o,"server_name"),"home.example")==0 && strcmp(obj_string(o,"path"),"/private-query")==0,"encrypted Home reset");}
  else{check(obj_string(o,"host")[0]=='\0' && obj_string(o,"protocol")[0]=='\0' && json_object_get_int_member(o,"port")==0,"other resolver carried into preset");}
  g_free(body);g_object_unref(p);
 }
 const char *invalid[]={"fastest","custom","dot","doh","doh3","unknown"};
 for(guint i=0;i<G_N_ELEMENTS(invalid);i++)check(linux_quick_dns_payload_v22(capture,"node \"quoted\"",invalid[i])==NULL,"unmeasured/configurable choice bypassed details");
 const char *bad_ids[]={"","replacement","NODE \"quoted\""};
 for(guint i=0;i<G_N_ELEMENTS(bad_ids);i++)check(linux_quick_dns_payload_v22(capture,bad_ids[i],"rescue")==NULL,"replacement owner accepted");
 json_object_unref(capture);return 0;
}
'''

def linux(directory):
    product=section(read("client/linux/routervpn-gtk-product-v5.c"),r"^static char \*dns_policy_payload_v5\(.*?^\}")
    source=read("client/linux/routervpn-unified-shell-v8.inc")
    helper=section(source,r"^static char \*linux_quick_dns_payload_v22\(.*?^\}")
    string_reader=section(read("client/linux/routervpn-gtk-product.c"),r"^static const char \*obj_string\(.*?^\}")
    transform=load_transform("linux_quick_dns_transform","client/linux/apply-session-mutation.py")
    transform.apply(ROOT/"client/linux/routervpn-unified-shell-v8.inc",directory/"unified.inc")
    callback=section((directory/"unified.inc").read_text(),r"^static void linux_unified_dns_changed_v8\(.*?^\}")
    assert callback.index("*displayed=g_strdup")<callback.index('api_request("/api/dns/policy","GET"')
    assert 'routervpn_require_mutation_idle(state->app,"changing DNS policy")' in callback
    assert 'linux_quick_dns_payload_v22(json_node_get_object(root),displayed,mode)' in callback
    assert 'strcmp(selected,"fastest")==0' in callback and 'refresh_dns_page_v5(state->app);return;' in callback
    flags=subprocess.check_output(["pkg-config","--cflags","--libs","json-glib-1.0"],text=True).split()
    variants={"shipping":helper,
              "reset-home":helper.replace('strcmp(mode,"home") == 0 && strcmp(obj_string(captured,"mode"),"home") == 0',"FALSE"),
              "carry-other-resolver":helper.replace('strcmp(mode,"home") == 0 && strcmp(obj_string(captured,"mode"),"home") == 0','strcmp(mode,"home") == 0'),
              "replace-owner":helper.replace('dns_policy_payload_v5(captured,displayed,mode','dns_policy_payload_v5(captured,obj_string(captured,"profile_id"),mode')}
    for name,body in variants.items():
        assert name=="shipping" or body!=helper
        if name=="replace-owner":body=body.replace('gboolean retained =','(void)displayed;\n    gboolean retained =')
        path,binary=directory/(name+".c"),directory/name
        path.write_text("#include <stdlib.h>\n#include <string.h>\n#include <json-glib/json-glib.h>\n"+string_reader+"\n"+product+"\n"+body+"\n"+C_TEST,encoding="utf-8")
        run(["cc","-Wall","-Wextra","-Werror",str(path),"-o",str(binary),*flags])
        run([str(binary)],broken=name!="shipping")

if __name__=="__main__":
    parser=argparse.ArgumentParser();parser.add_argument("--platform",required=True,choices=("windows","macos","linux"));parser.add_argument("--shell",default="pwsh");args=parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="routervpn-quick-dns-") as temp:
        directory=Path(temp)
        if args.platform=="windows":windows(directory,args.shell)
        else:globals()[args.platform](directory)
    print(f"{args.platform} compact DNS owner, encrypted Home preservation and negative controls: PASS")
