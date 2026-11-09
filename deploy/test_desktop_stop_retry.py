#!/usr/bin/env python3
"""Execute shipping transformed Retry Disconnect selectors and captured actions.

UI/HTTP boundaries are modeled; the platform JSON runtimes and actual composed
callback bodies execute. Real controller ownership is covered by Go tests.
"""
from __future__ import annotations
import argparse
from pathlib import Path
import subprocess
import tempfile
from test_desktop_startup_settings import ROOT, read, run, section, windows_adapter_import
from test_desktop_protection_settings import load_transform

PS_TEST = r'''
$ErrorActionPreference='Stop'
$script:button=[pscustomobject]@{Content='Connect';IsEnabled=$true}
$script:busy=$false;$script:UnifiedProtectionPending=$false;$script:UnifiedAsyncOwnedStopRetry=$false
$script:posts=@();$script:gets=0;$script:starts=0;$script:cancels=0
function Control($Name){return $script:button}
function UnifiedAsyncBusy{return $script:busy}
function Log($Text){}
function RefreshProduct{}
function Api($Path,$Timeout){if($Path-cne'/api/status'){throw 'Unexpected GET'};$script:gets++;return $script:status}
function StartUnifiedApiAsync($Label,$Path,$Method,$Body,$Timeout,$OnSuccess,$OnFailure,$OnFinally){$script:posts+=,@{Path=$Path;Body=$Body};if($script:refuse){&$OnFailure '409 expired Stop receipt'};return $true}
function CancelUnifiedApiAsync($DisconnectAfter){$script:cancels++;return $true}
function UnifiedSelectedProfile{$script:starts++;return $null}
$token='0123456789abcdef0123456789abcdef';$newToken='bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'
foreach($phase in @('failed','off','connected')){
 $script:status=[pscustomobject]@{connected=($phase-ceq'connected');phase=$phase;stop_pending=$true;stop_token=$token}
 SetUnifiedStopRetryPresentation $script:status
 if($script:button.Content-cne'Retry Disconnect'-or-not$script:button.IsEnabled-or$script:UnifiedStopRetryToken-cne$token){throw 'Pending cleanup missing from primary button'}
 foreach($fresh in @([pscustomobject]@{connected=$false;phase='off';stop_pending=$false},[pscustomobject]@{connected=$true;phase='connected';stop_pending=$true;stop_token=$newToken})){
  $script:status=$fresh;$script:posts=@();$script:gets=0;$script:refuse=$true
  UnifiedConnect
  if($script:posts.Count-ne1-or$script:posts[0].Path-cne'/api/disconnect/retry'-or$script:posts[0].Body.stop_token-cne$token-or$script:gets-ne0-or$script:starts-ne0-or$script:cancels-ne0){throw 'Rendered Retry changed action/owner or preempted replacement'}
 }
}
$script:status=[pscustomobject]@{connected=$false;phase='stopping';stop_pending=$true;stop_token=$token};SetUnifiedStopRetryPresentation $script:status
if($script:button.IsEnabled-or$script:button.Content-cne'Disconnecting…'){throw 'Stopping allowed duplicate retry'}
foreach($bad in @([pscustomobject]@{stop_pending='true';stop_token=$token},[pscustomobject]@{stop_pending=$true;stop_token='bad'},[pscustomobject]@{stop_pending=$true;stop_token=4})){
 SetUnifiedStopRetryPresentation $bad
 if($script:button.IsEnabled-or$script:UnifiedStopRetryToken){throw 'Malformed receipt enabled an action'}
}
$script:status=[pscustomobject]@{connected=$false;phase='failed';stop_pending=$true;stop_token=$token};$script:UnifiedProtectionPending=$true
SetUnifiedStopRetryPresentation $script:status
if(-not$script:button.IsEnabled){throw 'Owned cleanup inaccessible during protection recovery'}
$script:UnifiedStopRetryToken='';$script:posts=@();UnifiedConnect
if($script:posts.Count-ne1-or$script:posts[0].Path-cne'/api/disconnect/retry'){throw 'Fresh owned retry missing'}
$script:status=[pscustomobject]@{connected=$false;phase='off';stop_pending=$false};$script:posts=@();UnifiedConnect
if($script:starts-ne0-or$script:posts.Count-ne0){throw 'Protection pending admitted Connect'}
$script:UnifiedProtectionPending=$false;$script:status=[pscustomobject]@{connected=$true;phase='connected';stop_pending=$false};UnifiedConnect
if($script:posts.Count-ne1-or$script:posts[0].Path-cne'/api/disconnect'){throw 'Ordinary Disconnect changed'}
$script:status=[pscustomobject]@{connected=$false;phase='off';stop_pending=$false};UnifiedConnect
if($script:starts-ne1){throw 'Normal Connect no longer reaches selection'}
$script:busy=$true;$script:UnifiedStopRetryToken=$token;$script:posts=@();UnifiedConnect
if($script:cancels-ne0-or$script:posts.Count-ne0){throw 'Owned retry preempted another local operation'}
$script:UnifiedStopRetryToken='';$script:UnifiedAsyncOwnedStopRetry=$true;UnifiedConnect
if($script:cancels-ne0){throw 'In-flight owned retry entered generic cancellation'}
$script:busy=$false;$script:status=[pscustomobject]@{connected=$false;phase='failed';stop_pending=$true;stop_token=$token}
if(-not(Test-RouterVPNMutationBusyFromStatus $script:status)){throw 'Pending Stop left ordinary editor guard idle'}
AssertUnifiedProtectionMutationIdle $false
$caught=$false;try{AssertUnifiedProtectionMutationIdle $true}catch{$caught=$true};if(-not$caught){throw 'Protection On bypassed pending Stop'}
$script:status.connected=$true;$caught=$false;try{AssertUnifiedProtectionMutationIdle $false}catch{$caught=$true};if(-not$caught){throw 'Off cleanup bypassed connected guard'}
$script:status=[pscustomobject]@{connected=$false;phase='off';stop_pending=0}
if(-not(Test-RouterVPNMutationBusyFromStatus $script:status)){throw 'Malformed Stop state opened ordinary editor'}

'''
PS_ASYNC_TEST = r'''
$ErrorActionPreference='Stop'
Add-Type -AssemblyName System.Net.Http
$script:busy=$true;$script:UnifiedAsyncOwnedStopRetry=$true;$script:UnifiedAsyncDisconnectAfterCancel=$true
$script:UnifiedAsyncCancelled=$false;$script:UnifiedAsyncClosed=$false;$script:UnifiedAsyncCompleting=$false
$script:UnifiedAsyncPoller=[pscustomobject]@{};$script:UnifiedAsyncPoller|Add-Member ScriptMethod Stop {}
$script:UnifiedAsyncCts=[Threading.CancellationTokenSource]::new()
$script:UnifiedAsyncRequest=$null;$script:UnifiedAsyncSuccess=$null;$script:UnifiedAsyncFailure=$null;$script:UnifiedAsyncFinally=$null
$script:posts=0;$script:refreshes=0
function UnifiedAsyncBusy{return $script:busy}
function StopUnifiedComparisonProgress{}
function SetUnifiedAsyncUI($Busy,$Label){}
function RefreshProduct{$script:refreshes++}
function Log($Text){}
function StartUnifiedApiAsync{$script:posts++}
[void](CancelUnifiedApiAsync $true)
if($script:UnifiedAsyncDisconnectAfterCancel){throw 'Retry cancellation queued unconditional Stop'}
# Even an obsolete queued flag cannot broaden a retry at completion.
$script:UnifiedAsyncDisconnectAfterCancel=$true
$response=[Net.Http.HttpResponseMessage]::new([Net.HttpStatusCode]::Conflict)
$response.Content=[Net.Http.StringContent]::new('expired original Stop receipt')
$completion=[Threading.Tasks.TaskCompletionSource[Net.Http.HttpResponseMessage]]::new();$completion.SetResult($response)
$script:UnifiedAsyncTask=$completion.Task
CompleteUnifiedApiAsync
if($script:posts-ne0-or$script:refreshes-ne1){throw 'Retry completion dispatched a broader action'}
'''

def windows(directory, shell):
    composed=directory/'composed.ps1'
    builder=directory/'compose.ps1'
    builder.write_text("param($Output)\n$ErrorActionPreference='Stop'\n"+windows_adapter_import()+f". '{ROOT}/client/RouterVPN-Windows-SessionMutation.ps1'\n"+f"$product=Convert-RouterVPNWindowsProductSessionMutation -Source ([IO.File]::ReadAllText('{ROOT}/client/RouterVPN-Windows-Product-v2.ps1'))\n"+f"$unified=Convert-RouterVPNWindowsUnifiedSessionMutation -Source ([IO.File]::ReadAllText('{ROOT}/client/RouterVPN-Windows-UnifiedShell.ps1'))\n"+r'''
. ([ScriptBlock]::Create($unified))
$composed=Add-RouterVPNUnifiedWindowsShell -ProductSource $product
$tokens=$null;$errors=$null
[void][System.Management.Automation.Language.Parser]::ParseInput($composed,[ref]$tokens,[ref]$errors)
if($errors.Count){throw ($errors.Message -join '; ')}
[IO.File]::WriteAllText($Output,$composed,[Text.UTF8Encoding]::new($false))
''',encoding='utf-8-sig')
    run([shell,'-NoProfile','-File',str(builder),str(composed)])
    source=composed.read_text()
    functions='\n'.join(section(source,r'^function '+name+r'(?:\([^\n]*\))?\{.*?^\}') for name in ['GetUnifiedStopRetryToken','TestUnifiedProtectionStatusBusy','AssertUnifiedProtectionMutationIdle','SetUnifiedStopRetryPresentation','StartUnifiedStopRetry','UnifiedConnect'])
    functions += '\n'+'\n'.join(section(source,r'^function '+name+r'[^\n]*') for name in ['Test-RouterVPNMutationBusyFromStatus','Test-RouterVPNMutationBusy','Assert-RouterVPNMutationIdle'])
    assert 'SetUnifiedStopRetryPresentation $Status' in source
    assert '$script:UnifiedAsyncOwnedStopRetry=($Path-ceq\'/api/disconnect/retry\')' in source
    for name,body in {'shipping':functions,'ignore-pending':functions.replace("if($Token){","if($false){"),'lose-rendered-intent':functions.replace('$CapturedRetry=[string]$script:UnifiedStopRetryToken',"$CapturedRetry=''"),'unconditional-stop':functions.replace("'/api/disconnect/retry'","'/api/disconnect'")}.items():
        assert name=='shipping' or body!=functions
        path=directory/(name+'.ps1');path.write_text(body+'\n'+PS_TEST,encoding='utf-8-sig')
        run([shell,'-NoProfile','-File',str(path)],broken=name!='shipping')
    callbacks='\n'.join(section(source,r'^function '+name+r'(?:\([^\n]*\))?\{.*?^\}') for name in ['CancelUnifiedApiAsync','CompleteUnifiedApiAsync'])
    for name,body in {'async-shipping':callbacks,'async-cancel-broadens':callbacks.replace('(-not$script:UnifiedAsyncOwnedStopRetry -and ($script:UnifiedAsyncDisconnectAfterCancel -or $DisconnectAfter))','($script:UnifiedAsyncDisconnectAfterCancel -or $DisconnectAfter)'),'async-finally-broadens':callbacks.replace('(-not$script:UnifiedAsyncOwnedStopRetry -and $script:UnifiedAsyncDisconnectAfterCancel)','$script:UnifiedAsyncDisconnectAfterCancel')}.items():
        assert name=='async-shipping' or body!=callbacks
        path=directory/(name+'.ps1');path.write_text(body+'\n'+PS_ASYNC_TEST,encoding='utf-8-sig')
        run([shell,'-NoProfile','-File',str(path)],broken=name!='async-shipping')
    # Execute the same Windows managed target validator used before native IPC.
    validator=section(read('client/RouterVPN-Windows-ControllerTransport.cs'),r'        internal static void ValidateTarget\(.*?        private static byte Method')
    validator=validator[:validator.index('        private static byte Method')]
    managed=directory/'target.ps1';managed.write_text("$ErrorActionPreference='Stop'\nAdd-Type @'\nusing System; using System.Text; public static class RetryTarget { static UTF8Encoding UTF8 = new UTF8Encoding(false,true); static Exception ProtocolError(){return new Exception(\"invalid target\");}\n"+validator.replace('internal static void','public static void')+"\n}\n'@\n[RetryTarget]::ValidateTarget('/api/disconnect/retry')\nforeach($target in @('/api/disconnect/../retry','/api/%64isconnect/retry','https://other/api/disconnect/retry','/api/controller/retry')){$caught=$false;try{[RetryTarget]::ValidateTarget($target)}catch{$caught=$true};if(-not$caught){throw 'Foreign retry route accepted'}}\n",encoding='utf-8-sig')
    run([shell,'-NoProfile','-File',str(managed)])

SWIFT_BOUNDARY = r'''
class NSButton { var title=""; var isEnabled=true }
struct FixtureQueue: Sendable { enum QoS {case userInitiated}; static func global(qos:QoS)->FixtureQueue{FixtureQueue()}; static var main:FixtureQueue{FixtureQueue()}; func async(execute:()->Void){execute()} }
typealias DispatchQueue = FixtureQueue
final class FixtureLabel {var stringValue=""}
final class FixtureAPI {
 var status:[String:Any]=[:];var gets=0;var paths:[String]=[];var bodies:[[String:Any]]=[];var refused=false
 func json(_ path:String,timeout:Double=0)throws->Any{gets+=1;return status}
 func request(_ path:String,method:String,body:[String:Any],timeout:Double)throws->Data{paths.append(path);bodies.append(body);if refused{throw NSError(domain:"expired",code:409)};return Data()}
}
final class Fixture {
 let api=FixtureAPI();let button=MacUnifiedConnectButton();let errorLabel=FixtureLabel();var starts=0
 func findUnifiedView(_ id:String)->AnyObject?{button}
 func appendHelp(_ value:String){}
 func refreshAll(){}
 func refreshUnifiedChrome(){}
 func startUnifiedSelectedMode(){starts+=1}
 func requireMutationIdle(_ action:String)throws{if mutationBusy(from:api.status){throw NSError(domain:action,code:409)}}
 func protection(_ enabled:Bool)throws{try requireUnifiedProtectionIdle(enabled:enabled)}
'''
SWIFT_TEST=r'''
func check(_ value:Bool,_ message:String){if !value{fatalError(message)}}
let token="0123456789abcdef0123456789abcdef", replacement="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
for phase in ["failed","off","connected"]{
 let original:[String:Any]=["connected":phase=="connected","phase":phase,"stop_pending":true,"stop_token":token]
 let paint=productStopRetryPresentation(original,busy:false)
 check(paint.title=="Retry Disconnect" && paint.enabled && paint.token==token,"pending primary action missing")
 for fresh:[String:Any] in [["connected":false,"phase":"off","stop_pending":false],["connected":true,"phase":"connected","stop_pending":true,"stop_token":replacement]]{
  let fixture=Fixture();fixture.button.stopRetryToken=paint.token;fixture.api.status=fresh;fixture.api.refused=true;fixture.connectUnified()
  check(fixture.api.paths==["/api/disconnect/retry"] && fixture.api.bodies[0]["stop_token"] as? String==token && fixture.api.gets==0 && fixture.starts==0,"rendered Retry changed owner/action after status changed")
 }
}
for bad:[String:Any] in [["stop_pending":"true","stop_token":token],["stop_pending":1,"stop_token":token],["stop_pending":true,"stop_token":"bad"],["stop_pending":true]]{
 let paint=productStopRetryPresentation(bad,busy:false);check(!paint.enabled && paint.token==nil,"malformed receipt enabled action")
 let fixture=Fixture();fixture.api.status=bad;fixture.connectUnified();check(fixture.api.paths.isEmpty && fixture.starts==0,"malformed status reached action")
}
check(!productStopRetryPresentation(["phase":"stopping","stop_pending":true,"stop_token":token],busy:true).enabled,"Stop allowed duplicate retry")
let fresh=Fixture();fresh.api.status=["connected":false,"phase":"failed","stop_pending":true,"stop_token":token];fresh.connectUnified();check(fresh.api.paths==["/api/disconnect/retry"],"fresh pending missing")
let connected=Fixture();connected.api.status=["connected":true,"phase":"connected","stop_pending":false];connected.connectUnified();check(connected.api.paths==["/api/disconnect"],"ordinary Disconnect changed")
let off=Fixture();off.api.status=["connected":false,"phase":"off","stop_pending":false];off.connectUnified();check(off.starts==1 && off.api.paths.isEmpty,"ordinary Connect changed")
let recovery=Fixture();recovery.api.status=["connected":false,"phase":"failed","stop_pending":true,"stop_token":token]
check(mutationBusy(from:recovery.api.status),"pending Stop left editor idle")
try recovery.protection(false)
var caught=false;do{try recovery.protection(true)}catch{caught=true};check(caught,"Protection On bypassed pending Stop")
recovery.api.status["connected"]=true;caught=false;do{try recovery.protection(false)}catch{caught=true};check(caught,"Off cleanup bypassed connected guard")
check(mutationBusy(from:["connected":false,"phase":"off","stop_pending":0]),"malformed Stop state left editor idle")

'''

def macos(directory):
    transform=load_transform('mac_stop_retry_transform','client/macos/macos-session-mutation-transform.py')
    source=transform.transform(read('client/macos/RouterVPNMacUnifiedShell.swift'),'unified')
    helpers=section(source,r'^final class MacUnifiedConnectButton: NSButton \{.*?^\}')+'\n'+section(source,r'^func productStopRetryToken\(.*?^\}')+'\n'+section(source,r'^func productStopRetryPresentation\(.*?^\}')
    product=transform.transform(read('client/macos/RouterVPNMacProduct.swift'),'product')
    helpers += '\nstruct MacViaEntryCandidateReservation: Sendable {static let shared=MacViaEntryCandidateReservation();let active=false}\n'+section(product,r'^    func mutationBusy\(from status:.*?^    \}')+'\n'
    protection=section(source,r'^    private func requireUnifiedProtectionIdle\(.*?^    \}')
    callback=section(source,r'^    @objc func connectUnified\(.*?^    \}').replace('@objc ','').replace('DispatchQueue.','FixtureQueue.')
    assert 'button.stopRetryToken = stopPresentation.token' in source and 'button.isEnabled = stopPresentation.enabled' in source
    assert 'let busy = self.mutationBusy(from: statusObject) || stopPresentation.token != nil || !stopPresentation.enabled' in source
    for name,body in {'shipping':helpers+SWIFT_BOUNDARY+protection+'\n'+callback+'\n}\n','ignore-pending':(helpers+SWIFT_BOUNDARY+protection+'\n'+callback+'\n}\n').replace('if let token { return ("Retry Disconnect", true, token) }','if false { return ("Retry Disconnect", true, token) }'),'lose-rendered-intent':(helpers+SWIFT_BOUNDARY+protection+'\n'+callback+'\n}\n').replace('let capturedRetryToken = (findUnifiedView("unified-connect") as? MacUnifiedConnectButton)?.stopRetryToken','let capturedRetryToken: String? = nil'),'unconditional-stop':(helpers+SWIFT_BOUNDARY+protection+'\n'+callback+'\n}\n').replace('"/api/disconnect/retry"','"/api/disconnect"')}.items():
        path,binary=directory/(name+'.swift'),directory/name
        # Boundary base type must precede the actual shipping NSButton subclass.
        prelude='import Foundation\nimport CoreFoundation\nclass NSButton { var title=""; var isEnabled=true }\n'
        path.write_text(prelude+body.replace('class NSButton { var title=""; var isEnabled=true }','')+SWIFT_TEST)
        run(['swiftc','-swift-version','6','-module-cache-path',str(directory/'swift-cache'),str(path),'-o',str(binary)])
        run([str(binary)],broken=name!='shipping')

C_BOUNDARY=r'''
#include <json-glib/json-glib.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef struct {int unused;} App;
typedef GObject GtkButton;
typedef struct {App *app;GObject *connect,*status,*node,*kill_switch,*multihop,*mode,*dns;gboolean syncing;} LinuxUnifiedV8;
#define GTK_BUTTON(v) (v)
#define GTK_LABEL(v) (v)
static void gtk_button_set_label(GObject *o,const char *s){g_object_set_data_full(o,"label",g_strdup(s),g_free);}
static void gtk_label_set_text(GObject *o,const char *s){(void)o;(void)s;}
static void gtk_widget_set_sensitive(GObject *o,gboolean v){g_object_set_data(o,"enabled",GINT_TO_POINTER(v));}
typedef struct {char *data;} Buffer;
static gboolean async_busy,async_connect,async_stop;static int posts,gets,starts;static char *posted_path,*posted_body;static const char *fresh;
static gboolean linux_async_busy_v16(App *a){(void)a;return async_busy;}
static gboolean linux_async_stopping_v16(App *a){(void)a;return async_stop;}
static gboolean linux_async_connecting_v16(App *a){(void)a;return async_connect;}
static void append_diag(App *a,const char *s){(void)a;(void)s;}
static void post_and_log(App *a,const char *path,const char *body,long timeout,const char *label){(void)a;(void)timeout;(void)label;posts++;g_free(posted_path);g_free(posted_body);posted_path=g_strdup(path);posted_body=g_strdup(body);}
static char *json_string_body(const char *key,const char *value){JsonObject *o=json_object_new();json_object_set_string_member(o,key,value);JsonNode *n=json_node_new(JSON_NODE_OBJECT);json_node_take_object(n,o);char *s=json_to_string(n,FALSE);json_node_free(n);return s;}
static JsonNode *parse_json(const char *s){JsonParser *p=json_parser_new();if(!json_parser_load_from_data(p,s,-1,NULL)){g_object_unref(p);return NULL;}JsonNode *n=json_node_copy(json_parser_get_root(p));g_object_unref(p);return n;}
static const char *obj_string(JsonObject *o,const char *k){return json_object_has_member(o,k)?json_object_get_string_member(o,k):"";}
static gboolean routervpn_phase_disconnecting(const char *p){return strstr(p,"stopping")!=NULL||strstr(p,"disconnecting")!=NULL;}
static gboolean api_request(const char *path,const char *method,const char *body,long timeout,Buffer *out,char **err){(void)body;(void)timeout;(void)err;if(strcmp(path,"/api/status")||strcmp(method,"GET"))abort();gets++;out->data=strdup(fresh);return TRUE;}
static void check(gboolean v,const char *m){if(!v){fprintf(stderr,"%s\n",m);exit(1);}}
'''
C_TEST=r'''
int main(void){
 App app={0};GObject *button=g_object_new(G_TYPE_OBJECT,NULL),*other=g_object_new(G_TYPE_OBJECT,NULL);LinuxUnifiedV8 state={&app,button,other,other,other,other,other,other,FALSE};
 const char *token="0123456789abcdef0123456789abcdef";
 const char *values[]={"{\"phase\":\"off\",\"connected\":false,\"stop_pending\":false}","{\"phase\":\"connected\",\"connected\":true,\"stop_pending\":true,\"stop_token\":\"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\"}"};
 for(size_t i=0;i<2;i++){
  fresh="{\"phase\":\"failed\",\"connected\":false,\"stop_pending\":true,\"stop_token\":\"0123456789abcdef0123456789abcdef\"}";
  linux_unified_refresh_v8(&state);
  check(!strcmp(g_object_get_data(button,"label"),"Retry Disconnect")&&GPOINTER_TO_INT(g_object_get_data(button,"enabled")),"actual refresh omitted enabled Retry Disconnect");
  fresh=values[i];posts=gets=starts=0;
  linux_unified_connect_v8(NULL,&state);
  check(posts==1&&gets==0&&starts==0&&!strcmp(posted_path,"/api/disconnect/retry"),"rendered retry changed action");
  JsonNode *body=parse_json(posted_body);check(!strcmp(obj_string(json_node_get_object(body),"stop_token"),token),"rendered retry changed owner");json_node_free(body);
 }
 g_object_set_data(button,"routervpn-stop-retry-token",NULL);
 const char *bad[]={"{\"stop_pending\":\"true\"}","{\"stop_pending\":1}","{\"stop_pending\":true,\"stop_token\":\"bad\"}","{\"stop_pending\":true}"};
 for(size_t i=0;i<G_N_ELEMENTS(bad);i++){fresh=bad[i];posts=starts=0;linux_unified_connect_v8(NULL,&state);check(posts==0&&starts==0,"malformed receipt reached action");}
 fresh=values[1];posts=0;linux_unified_connect_v8(NULL,&state);check(posts==1&&!strcmp(posted_path,"/api/disconnect/retry"),"fresh owned retry missing");
 fresh="{\"connected\":true,\"phase\":\"connected\",\"stop_pending\":false}";posts=0;linux_unified_connect_v8(NULL,&state);check(posts==1&&!strcmp(posted_path,"/api/disconnect"),"ordinary Disconnect changed");
 fresh=values[0];starts=0;linux_unified_connect_v8(NULL,&state);check(starts==1,"ordinary Connect changed");
 g_object_set_data_full(button,"routervpn-stop-retry-token",g_strdup(token),g_free);async_busy=async_connect=TRUE;posts=0;linux_unified_connect_v8(NULL,&state);check(posts==0,"owned retry preempted replacement locally");
 async_busy=async_connect=FALSE;fresh="{\"phase\":\"stopping\",\"stop_pending\":true,\"stop_token\":\"0123456789abcdef0123456789abcdef\"}";linux_unified_refresh_v8(&state);check(!GPOINTER_TO_INT(g_object_get_data(button,"enabled")),"stopping enabled a duplicate retry");
 fresh=bad[0];linux_unified_refresh_v8(&state);check(!GPOINTER_TO_INT(g_object_get_data(button,"enabled"))&&g_object_get_data(button,"routervpn-stop-retry-token")==NULL,"invalid refresh retained actionable token");
 fresh="{\"phase\":\"failed\",\"connected\":false,\"stop_pending\":true,\"stop_token\":\"0123456789abcdef0123456789abcdef\"}";
 check(linux_protection_mutation_busy_v26(&app,TRUE),"pending Stop left ordinary protection mutation idle");check(!linux_protection_mutation_busy_v26(&app,FALSE),"owned Off cleanup blocked by Stop fence");
 fresh=values[1];check(linux_protection_mutation_busy_v26(&app,FALSE),"Off cleanup bypassed connected guard");fresh=bad[1];check(linux_protection_mutation_busy_v26(&app,TRUE),"malformed Stop left ordinary editor idle");
 g_object_unref(button);g_object_unref(other);g_free(posted_path);g_free(posted_body);return 0;
}
'''

def linux(directory):
    transform=load_transform('linux_stop_retry_transform','client/linux/apply-session-mutation.py')
    target=directory/'routervpn-unified-shell-v8.inc';transform.apply(ROOT/'client/linux/routervpn-unified-shell-v8.inc',target)
    source=target.read_text()
    core=directory/'routervpn-gtk-product.c';transform.apply(ROOT/'client/linux/routervpn-gtk-product.c',core)
    core_source=core.read_text()
    guards='\n'.join(section(core_source,r'^static gboolean '+name+r'\(.*?^\}') for name in ['routervpn_phase_busy','routervpn_mutation_busy_from_status','routervpn_mutation_busy'])
    helpers=guards+'\nstatic const char *linux_stop_retry_token_v26(JsonObject *,gboolean *);\n'+section(source,r'^static gboolean linux_protection_mutation_busy_v26\(App \*app, gboolean enabled\) \{.*?^\}')+'\n'+section(source,r'^static const char \*linux_stop_retry_token_v26\(.*?^\}')+'\n'+section(source,r'^static void linux_unified_retry_stop_v26\(.*?^\}')
    callback=section(source,r'^static void linux_unified_connect_v8\(.*?^\}')
    callback=callback[:callback.index('    if(!routervpn_require_mutation_idle')]+ '    starts++;\n}\n'
    assert 'disconnecting?"Disconnecting…":retry!=NULL?"Retry Disconnect"' in source
    assert 'g_object_set_data_full(G_OBJECT(state->connect),"routervpn-stop-retry-token",g_strdup(retry),g_free)' in source
    assert 'busy=routervpn_mutation_busy_from_status(obj)||retry!=NULL||!status_ok' in source
    assert '/api/disconnect/retry' not in read('client/linux/routervpn-async-actions-v16.inc'), 'owned retry must not gain unconditional preemption'
    flags=subprocess.check_output(['pkg-config','--cflags','--libs','json-glib-1.0'],text=True).split()
    refresh=section(source,r'^static gboolean linux_unified_refresh_v8\(gpointer data\) \{.*?^\}')
    refresh=refresh[:refresh.index('    out=(Buffer){0}')]+ '    return G_SOURCE_CONTINUE;\n}\n'
    code=helpers+'\n'+callback+'\n'+refresh
    for name,body in {'shipping':code,'lose-rendered-intent':code.replace('const char *captured_retry=g_object_get_data(G_OBJECT(state->connect),"routervpn-stop-retry-token");','const char *captured_retry=NULL;'),'unconditional-stop':code.replace('"/api/disconnect/retry"','"/api/disconnect"'),'preempt-local':code.replace('if(linux_async_busy_v16(state->app))','if(linux_async_busy_v16(state->app) && FALSE)')}.items():
        assert name=='shipping' or body!=code
        path,binary=directory/(name+'.c'),directory/name;path.write_text(C_BOUNDARY+body+C_TEST)
        run(['cc','-D_DEFAULT_SOURCE','-Wall','-Wextra','-Werror',str(path),'-o',str(binary)]+flags)
        run([str(binary)],broken=name!='shipping')


def contracts():
    paths=['.github/workflows/'+name for name in ['release-candidate.yml','windows-native-contract.yml','macos-native-app.yml','linux-native-app.yml']]
    files={path:read(path) for path in paths}
    def validate(files):
        release=files[paths[0]]
        for platform,job in [('windows','windows-native-smoke'),('macos','macos'),('linux','linux')]:
            body=section(release,r'^  '+job+r':\n.*?(?=^  [a-zA-Z]|\Z)')
            commands=[f'python3 deploy/test_desktop_stop_retry.py --platform {platform}'] if platform!='windows' else [f'python deploy/test_desktop_stop_retry.py --platform windows --shell {shell}' for shell in ['pwsh','powershell.exe']]
            for command in commands:
                assert body.count(command)==1, 'release lost native owned Stop retry gate: '+command
                focused=files[paths[1] if platform=='windows' else paths[2] if platform=='macos' else paths[3]]
                assert focused.count(command)==1, 'focused workflow lost native owned Stop retry gate: '+command
                if platform=='windows':
                    assert body.split(command,1)[1].lstrip().startswith('if ($LASTEXITCODE -ne 0)'), 'PowerShell failure no longer blocks release'
            for text in [body, focused]:
                gate=section(text,r'^      - name: Owned Stop retry preserves the displayed cleanup receipt\n.*?(?=^      - |\Z)')
                assert 'continue-on-error:' not in gate and '\n        if:' not in gate, 'owned retry gate became optional'
        assert 'python3 deploy/test_desktop_stop_retry.py --contracts-only' in release
    validate(files)
    for path,text in files.items():
        for line in text.splitlines():
            if 'deploy/test_desktop_stop_retry.py --platform' not in line:continue
            changed=dict(files);changed[path]=text.replace(line,'',1)
            try:validate(changed)
            except (AssertionError, RuntimeError):pass
            else:raise AssertionError('removed native retry gate was accepted: '+path)
    main=read('cmd/client/main.go');retry=read('cmd/client/controller_stop_retry.go')
    assert 'h.HandleFunc("/api/disconnect/retry", a.retryDisconnect)' in main
    assert retry.index('a.captureStopRetryContext(r.Context(), request.StopToken)')<retry.index('a.cancelCapturedStopContext(r.Context(), receipt)')<retry.index('a.stopModeWithDNSReceiptContext(r.Context(), false, receipt)')
    assert 'a.cancelConnectionOperation()' not in retry
    assert 'receipt != expected' in read('cmd/client/session_dns_stop.go')
    assert 'return a.stopModeWithDNSReceipt(holdKillSwitch, nil)' in main
    # Both public entry points must keep the same caller/receipt through
    # cancellation, operation admission and cleanup. Runtime Go controls also
    # execute these handlers with held original workers and stale receipts.
    def public_stop_chain(source, name, reason):
        signature='func (a *app) '+name+'(w http.ResponseWriter, r *http.Request)'
        if signature not in source:return False
        body=source.split(signature,1)[1].split('\nfunc ',1)[0]
        calls=[f'a.capturePublicStopContext(r.Context(), "{reason}")',
               'a.beginCapturedPublicStopContext(r.Context(), receipt)',
               'finishViaEntryCancellationContext(r.Context(), a)',
               'a.stopModeWithDNSReceiptContext(r.Context(), false, receipt)']
        if any(body.count(call)!=1 for call in calls):return False
        return [body.index(call) for call in calls]==sorted(body.index(call) for call in calls) and 'a.cancelConnectionOperation()' not in body and 'a.operationMu.Lock()' not in body
    for source,name,reason in [(main,'disconnect',''),(read('cmd/client/extras.go'),'emergencyStop','emergency-stop')]:
        assert public_stop_chain(source,name,reason)
        for original,replacement in [
            (f'a.capturePublicStopContext(r.Context(), "{reason}")',f'a.capturePublicStopContext(context.Background(), "{reason}")'),
            ('a.beginCapturedPublicStopContext(r.Context(), receipt)','a.beginCapturedPublicStopContext(r.Context(), nil)'),
            ('finishViaEntryCancellationContext(r.Context(), a)','finishViaEntryCancellation(a)'),
            ('a.stopModeWithDNSReceiptContext(r.Context(), false, receipt)','a.stopMode()'),
        ]:
            assert not public_stop_chain(source.replace(original,replacement,1),name,reason)
    assert 'context.WithTimeout(caller, 15*time.Second)' in main
    assert 'failure = dnsStop.finishCaptured(ctx, expected)' in main
    assert 'r.publicReserved && expected == nil && !t.dnsProofClosed' in read('cmd/client/session_dns_stop.go')
    print('Owned Stop retry: mandatory three-platform shipping gates and removal controls passed')

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--contracts-only',action='store_true');parser.add_argument('--platform',choices=['windows','macos','linux']);parser.add_argument('--shell',default='pwsh');args=parser.parse_args()
    if args.contracts_only:
        contracts();raise SystemExit(0)
    if args.platform is None:parser.error('--platform is required')
    with tempfile.TemporaryDirectory(prefix='routervpn-stop-retry-') as temp:
        directory=Path(temp)
        if args.platform=='windows':windows(directory,args.shell)
        elif args.platform=='macos':macos(directory)
        else:linux(directory)
    print(args.platform+': shipping owned Stop retry and causal negative controls passed')
