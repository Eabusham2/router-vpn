#!/usr/bin/env python3
"""Exercise shipping protection serializers against stale selections and secret copying."""
from __future__ import annotations

import argparse
import importlib.util
from pathlib import Path
import subprocess
import tempfile

from test_desktop_startup_settings import ROOT, read, run, section


PS_TEST = r'''
$ErrorActionPreference='Stop'
$script:sent=$null;$script:gets=0;$script:posts=0;$script:reject=$false
$script:captured=[pscustomobject]@{profile_id='node "quoted"';profile_token='captured-source';kill_switch_policy='always';password='never-copy'}
function global:Invoke-RestMethod {
    param($Uri,$Method,$ContentType,$Body,$TimeoutSec)
    if($Uri -cne 'http://127.0.0.1:8788/api/profile/protection'){throw 'Wrong protection route'}
    if($Method -ceq 'Get'){$script:gets++;return $script:captured}
    if($Method -cne 'Post'){throw 'Wrong method'}
    if($script:reject){throw 'Source changed before commit'}
    $script:posts++;$script:sent=$Body|ConvertFrom-Json;return $script:sent
}
foreach($enabled in @($true,$false)){
    $value=Set-RouterVPNProfileProtection -BaseUrl 'http://127.0.0.1:8788/' -DisplayedProfileID 'node "quoted"' -Enabled $enabled
    $keys=@($value.PSObject.Properties.Name|Sort-Object)
    if(($keys -join ',') -cne 'kill_switch_policy,profile_id,profile_token'){throw 'Private or unrelated data copied'}
    if($value.profile_id -cne 'node "quoted"' -or $value.profile_token -cne 'captured-source'){throw 'Lost source ownership'}
    $expected=if($enabled){'on-connect'}else{'off'}
    if($value.kill_switch_policy -cne $expected){throw 'Wrong policy'}
}
foreach($case in @('empty selection','different selection','different case','missing revision','server rejection')){
    $displayed='node "quoted"';$script:captured.profile_id=$displayed;$script:captured.profile_token='captured-source'
    $script:reject=$false;$before=$script:posts;$gets=$script:gets
    switch($case){
        'empty selection'{$displayed=''}
        'different selection'{$script:captured.profile_id='replacement'}
        'different case'{$script:captured.profile_id='NODE "quoted"'}
        'missing revision'{$script:captured.profile_token=''}
        'server rejection'{$script:reject=$true}
    }
    $caught=$false
    try{Set-RouterVPNProfileProtection -BaseUrl 'http://127.0.0.1:8788' -DisplayedProfileID $displayed -Enabled $true}catch{$caught=$true}
    if(-not$caught -or $script:posts -ne $before){throw "Unsafe edit accepted: $case"}
    if($case -eq 'empty selection' -and $script:gets -ne $gets){throw 'An empty displayed selection adopted the server node'}
}
'''


def windows(directory, shell):
    source = read("client/RouterVPN-Windows-ProfileSettings.ps1")
    function = section(source, r"^function global:Set-RouterVPNProfileProtection \{.*?^\}")
    callback = read("client/RouterVPN-Windows-UnifiedShell.ps1")
    assert "$DisplayedProfileID=[string]$RouterCombo.SelectedValue" in callback
    assert "-DisplayedProfileID $DisplayedProfileID -Enabled $On" in callback
    variants = {
        "shipping": function,
        "adopt-replacement": function.replace("[string]$captured.profile_id -cne $DisplayedProfileID", "$false"),
        "wrong-revision": function.replace("profile_token=[string]$captured.profile_token", "profile_token='unrelated-source'"),
        "copy-private": function.replace("-Body ($body | ConvertTo-Json -Compress)", "-Body ($captured | ConvertTo-Json -Compress)"),
    }
    for name, body in variants.items():
        if name != "shipping" and body == function:
            raise RuntimeError("PowerShell negative did not apply: " + name)
        path = directory / (name + ".ps1")
        path.write_text(body + PS_TEST, encoding="utf-8-sig")
        run([shell, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(path)], broken=name != "shipping")


SWIFT_TEST = r'''
func check(_ value: Bool, _ message: String) { if !value { fatalError(message) } }
let raw = try JSONSerialization.data(withJSONObject: ["profile_id":"node \"quoted\"", "profile_token":"captured-source", "kill_switch_policy":"always", "password":"never-copy"])
let captured = try JSONDecoder().decode(MacProfileProtectionSettings.self, from: raw)
for enabled in [true, false] {
    let data = try captured.saveData(displayedProfileID: "node \"quoted\"", enabled: enabled)
    let body = try JSONSerialization.jsonObject(with: data) as! [String: Any]
    check(Set(body.keys) == Set(["profile_id", "profile_token", "kill_switch_policy"]), "private/unrelated data copied")
    check(body["profile_id"] as? String == "node \"quoted\"" && body["profile_token"] as? String == "captured-source", "lost captured owner")
    check(body["kill_switch_policy"] as? String == (enabled ? "on-connect" : "off"), "wrong policy")
}
for displayed in ["", "replacement", "NODE \"quoted\""] {
    var rejected = false
    do { _ = try captured.saveData(displayedProfileID: displayed, enabled: true) } catch { rejected = true }
    check(rejected, "adopted a replacement selection")
}
let missing = MacProfileProtectionSettings(profileID: "node", profileToken: "", killSwitchPolicy: "off")
var rejected = false
do { _ = try missing.saveData(displayedProfileID: "node", enabled: true) } catch { rejected = true }
check(rejected, "missing source revision accepted")
'''


def load_transform(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def macos(directory):
    source = read("client/macos/RouterVPNProfileSettings.swift")
    function = section(source, r"^struct MacProfileProtectionSettings: Decodable, Sendable \{.*?^\}")
    module = load_transform("mac_protection_mutation", "client/macos/macos-session-mutation-transform.py")
    shell = module.transform(read("client/macos/RouterVPNMacUnifiedShell.swift"), "unified")
    callback = section(shell, r"^    @objc func toggleUnifiedKillSwitch\(.*?^    \}")
    assert callback.index("let displayedProfileID = routerIDs[index]") < callback.index("asyncAction")
    assert 'self.requireMutationIdle("changing persistent kill-switch policy")' in callback
    assert 'saveData(displayedProfileID: displayedProfileID, enabled: enabled)' in callback
    assert 'requestRaw("/api/profile/protection", body: body' in callback
    assert 'kill.state = valid ?' in shell and ': .mixed' in shell
    variants = {
        "shipping": function,
        "adopt-replacement": function.replace("profileID == displayedProfileID", "true"),
        "wrong-revision": function.replace('"profile_token": profileToken', '"profile_token": "unrelated-source"'),
    }
    for name, body in variants.items():
        if name != "shipping" and body == function:
            raise RuntimeError("Swift negative did not apply: " + name)
        path, binary = directory / (name + ".swift"), directory / name
        path.write_text("import Foundation\n" + body + SWIFT_TEST, encoding="utf-8")
        run(["swiftc", "-swift-version", "6", "-module-cache-path", str(directory / "swift-module-cache"), str(path), "-o", str(binary)])
        run([str(binary)], broken=name != "shipping")


C_TEST = r'''
static void check(gboolean value, const char *message) { if (!value) { g_printerr("%s\n",message); exit(1); } }
int main(void) {
    JsonObject *captured=json_object_new();
    json_object_set_string_member(captured,"profile_id","node \"quoted\"");
    json_object_set_string_member(captured,"profile_token","captured-source");
    json_object_set_string_member(captured,"password","never-copy");
    for(int enabled=0;enabled<=1;enabled++) {
        char *raw=linux_protection_payload_v21(captured,"node \"quoted\"",enabled);
        check(raw!=NULL,"payload missing");
        JsonParser *parser=json_parser_new();check(json_parser_load_from_data(parser,raw,-1,NULL),"invalid payload");
        JsonObject *body=json_node_get_object(json_parser_get_root(parser));
        check(json_object_get_size(body)==3 && !json_object_has_member(body,"password"),"private/unrelated fields copied");
        check(g_strcmp0(obj_string(body,"profile_id"),"node \"quoted\"")==0 && g_strcmp0(obj_string(body,"profile_token"),"captured-source")==0,"lost captured owner");
        check(g_strcmp0(obj_string(body,"kill_switch_policy"),enabled?"on-connect":"off")==0,"wrong policy");
        g_object_unref(parser);g_free(raw);
    }
    check(linux_protection_payload_v21(captured,"replacement",TRUE)==NULL,"replacement owner accepted");
    check(linux_protection_payload_v21(captured,"NODE \"quoted\"",TRUE)==NULL,"case-insensitive owner accepted");
    check(linux_protection_payload_v21(captured,"",TRUE)==NULL,"empty selection accepted");
    check(linux_protection_payload_v21(captured,NULL,TRUE)==NULL,"missing selection accepted");
    json_object_remove_member(captured,"profile_token");
    check(linux_protection_payload_v21(captured,"node \"quoted\"",TRUE)==NULL,"missing revision accepted");
    json_object_unref(captured);return 0;
}
'''


def linux(directory):
    source_path = ROOT / "client/linux/routervpn-unified-shell-v8.inc"
    module = load_transform("linux_protection_mutation", "client/linux/apply-session-mutation.py")
    module.apply(source_path, directory / "unified.inc")
    source = (directory / "unified.inc").read_text(encoding="utf-8")
    function = section(source, r"^static char \*linux_protection_payload_v21\(.*?^\}")
    string_reader = section(read("client/linux/routervpn-gtk-product.c"), r"^static const char \*obj_string\(.*?^\}")
    callback = section(source, r"^static void linux_unified_kill_changed_v8\(.*?^\}")
    assert callback.index("char *displayed = g_strdup") < callback.index('"/api/profile/protection", "GET"')
    assert 'routervpn_require_mutation_idle' in callback
    assert 'linux_protection_payload_v21(json_node_get_object(root), displayed, enabled)' in callback
    assert 'post_and_log(state->app,"/api/profile/protection",body' in callback
    assert 'gtk_toggle_button_set_inconsistent(GTK_TOGGLE_BUTTON(state->kill_switch), !valid)' in source
    flags = subprocess.check_output(["pkg-config", "--cflags", "--libs", "json-glib-1.0"], text=True).split()
    variants = {
        "shipping": function,
        "adopt-replacement": function.replace("strcmp(id, displayed) != 0", "id == NULL"),
        "wrong-revision": function.replace("json_builder_add_string_value(builder, token)", 'json_builder_add_string_value(builder, "unrelated-source")'),
    }
    for name, body in variants.items():
        if name != "shipping" and body == function:
            raise RuntimeError("GTK negative did not apply: " + name)
        path, binary = directory / (name + ".c"), directory / name
        path.write_text("#include <stdlib.h>\n#include <string.h>\n#include <json-glib/json-glib.h>\n" + string_reader + "\n" + body + C_TEST, encoding="utf-8")
        run(["cc", "-Wall", "-Wextra", "-Werror", str(path), "-o", str(binary), *flags])
        run([str(binary)], broken=name != "shipping")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--platform", required=True, choices=("windows", "macos", "linux"))
    parser.add_argument("--shell", default="pwsh")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="routervpn-protection-settings-") as temp:
        directory = Path(temp)
        if args.platform == "windows":
            windows(directory, args.shell)
        else:
            globals()[args.platform](directory)
    print(f"{args.platform} shipping protection capture, private-field preservation and negative controls: PASS")
