#!/usr/bin/env python3
"""Run the shipping native startup serializers; never copy a private node into Settings."""
from __future__ import annotations

import argparse
from pathlib import Path
import re
import subprocess
import tempfile
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]


def read(path):
    return (ROOT / path).read_text(encoding="utf-8")


def run(command, *, broken=False):
    result = subprocess.run(command, text=True, encoding="utf-8", errors="replace", capture_output=True, timeout=90)
    if (result.returncode != 0) != broken:
        raise RuntimeError(f"unexpected return {result.returncode}: {command}\n{result.stdout}\n{result.stderr}")


def section(source, pattern):
    match = re.search(pattern, source, re.M | re.S)
    if match is None:
        raise RuntimeError("shipping function is missing: " + pattern)
    return match.group(0)


PS_TEST = r'''
$ErrorActionPreference='Stop'
$script:sent=$null;$script:reject=$false
function global:Invoke-RestMethod {
    param($Uri,$Method,$ContentType,$Body,$TimeoutSec)
    if($script:reject){throw 'stale editor'}
    if($Uri -cne 'http://127.0.0.1:8788/api/profile/startup' -or $Method -cne 'Post'){throw 'Wrong startup route'}
    $script:sent=$Body|ConvertFrom-Json
    return $script:sent
}
$captured=[pscustomobject]@{profile_id='node "quoted"';profile_token='captured-source';node_kind='external';password='never-copy';startup_mode='manual';auto_connect=$false}
foreach($mode in @('manual','auto','last')){
    $automatic=$mode -ne 'manual'
    $value=Save-RouterVPNProfileStartup -BaseUrl 'http://127.0.0.1:8788/' -Captured $captured -StartupMode $mode -AutoConnect $automatic
    $keys=@($value.PSObject.Properties.Name|Sort-Object)
    if(($keys -join ',') -cne 'auto_connect,profile_id,profile_token,startup_mode'){throw 'Private or unrelated fields copied'}
    if($value.profile_id -cne $captured.profile_id -or $value.profile_token -cne 'captured-source'){throw 'Lost captured node/source'}
    if($value.startup_mode -cne $mode -or $value.auto_connect -isnot [bool] -or $value.auto_connect -ne $automatic){throw 'Lost selected startup policy'}
}
$caught=$false
try{Save-RouterVPNProfileStartup -BaseUrl 'http://127.0.0.1:8788' -Captured $null -StartupMode 'auto' -AutoConnect $true}catch{$caught=$true}
if(-not$caught){throw 'Missing capture accepted'}
$script:reject=$true;$caught=$false
try{Save-RouterVPNProfileStartup -BaseUrl 'http://127.0.0.1:8788' -Captured $captured -StartupMode 'auto' -AutoConnect $true}catch{$caught=$true}
if(-not$caught){throw 'Server rejection hidden'}
'''


def windows(directory, shell):
    source = read("client/RouterVPN-Windows-ProfileSettings.ps1")
    function = section(source, r"^function global:Save-RouterVPNProfileStartup \{.*?^\}")
    assert 'Name="StartupSettings"' in source
    assert "-Captured $externalStartup" in source and "$captured.node_kind -eq 'external'" in source
    xaml = re.search(r"\[xml\]\$xaml = @'\n(.*?)\n'@", source, re.S)
    assert xaml is not None
    window = ET.fromstring(xaml.group(1))
    panels = {element.attrib.get("Name"): element for element in window.iter() if element.attrib.get("Name")}
    assert panels["Startup"] in list(panels["StartupSettings"].iter())
    assert panels["AutoConnect"] in list(panels["StartupSettings"].iter())
    assert panels["Startup"] not in list(panels["NodeSettings"].iter())
    variants = {"shipping": function,
                "wrong-owner": function.replace("profile_token=[string]$Captured.profile_token", "profile_token='unrelated-source'"),
                "copy-private": function.replace("-Body ($body | ConvertTo-Json -Compress)", "-Body ($Captured | ConvertTo-Json -Compress)")}
    for name, body in variants.items():
        if name != "shipping" and body == function:
            raise RuntimeError("Windows negative mutation did not apply: " + name)
        path = directory / (name + ".ps1")
        path.write_text(body + PS_TEST, encoding="utf-8-sig")
        run([shell, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(path)], broken=name != "shipping")


SWIFT_TEST = r'''
func check(_ value: Bool, _ message: String) { if !value { fatalError(message) } }
let raw = try JSONSerialization.data(withJSONObject: ["profile_id":"node \"quoted\"", "profile_token":"captured-source", "node_kind":"external", "startup_mode":"manual", "auto_connect":false, "password":"never-copy"])
private let captured = try JSONDecoder().decode(MacProfileStartupSettings.self, from: raw)
for mode in ["manual", "auto", "last"] {
    let automatic = mode != "manual"
    let data = try captured.saveData(startupMode: mode, autoConnect: automatic)
    let body = try JSONSerialization.jsonObject(with: data) as! [String: Any]
    check(Set(body.keys) == Set(["profile_id", "profile_token", "startup_mode", "auto_connect"]), "private/unrelated data copied")
    check(body["profile_id"] as? String == captured.profileID && body["profile_token"] as? String == "captured-source", "lost captured owner")
    check(body["startup_mode"] as? String == mode && body["auto_connect"] as? Bool == automatic, "lost selected policy")
}
private let missing = MacProfileStartupSettings(profileID: "", profileToken: "", nodeKind: "external", startupMode: "manual", autoConnect: false)
var rejected = false
do { _ = try missing.saveData(startupMode: "auto", autoConnect: true) } catch { rejected = true }
check(rejected, "missing identity accepted")
'''


def macos(directory):
    source = read("client/macos/RouterVPNProfileSettings.swift")
    function = section(source, r"^private struct MacProfileStartupSettings: Decodable, Sendable \{.*?^\}")
    assert 'capturedStartup?.nodeKind == "external"' in source
    assert 'externalStartup.saveData(startupMode: settings.startupMode, autoConnect: settings.autoConnect)' in source
    assert 'requestRaw("/api/profile/startup", body: payload' in source
    for name, body in {"shipping": function, "wrong-owner": function.replace('"profile_token": profileToken', '"profile_token": "unrelated-source"')}.items():
        if name != "shipping" and body == function:
            raise RuntimeError("Swift negative mutation did not apply")
        path, binary = directory / (name + ".swift"), directory / name
        path.write_text("import Foundation\n" + body + SWIFT_TEST, encoding="utf-8")
        run(["swiftc", "-module-cache-path", str(directory / "swift-module-cache"), str(path), "-o", str(binary)])
        run([str(binary)], broken=name != "shipping")


C_TEST = r'''
static void check(gboolean value, const char *message) { if (!value) { g_printerr("%s\n",message); exit(1); } }
int main(void) {
    JsonObject *captured=json_object_new();
    json_object_set_string_member(captured,"profile_id","node \"quoted\"");
    json_object_set_string_member(captured,"profile_token","captured-source");
    json_object_set_string_member(captured,"password","never-copy");
    const char *modes[]={"manual","auto","last"};
    for(guint i=0;i<G_N_ELEMENTS(modes);i++) {
        gboolean automatic=i!=0;
        char *raw=profile_startup_payload_v7(captured,modes[i],automatic);
        check(raw!=NULL,"payload missing");
        JsonParser *parser=json_parser_new();
        check(json_parser_load_from_data(parser,raw,-1,NULL),"invalid payload");
        JsonObject *body=json_node_get_object(json_parser_get_root(parser));
        check(json_object_get_size(body)==4 && !json_object_has_member(body,"password"),"private/unrelated fields copied");
        check(g_strcmp0(obj_string(body,"profile_id"),"node \"quoted\"")==0 && g_strcmp0(obj_string(body,"profile_token"),"captured-source")==0,"lost captured owner");
        check(g_strcmp0(obj_string(body,"startup_mode"),modes[i])==0 && json_object_get_boolean_member(body,"auto_connect")==automatic,"lost startup policy");
        g_object_unref(parser);g_free(raw);
    }
    json_object_remove_member(captured,"profile_token");
    check(profile_startup_payload_v7(captured,"auto",TRUE)==NULL,"missing owner accepted");
    json_object_unref(captured);return 0;
}
'''


def linux(directory):
    source = read("client/linux/routervpn-profile-settings-v1.inc")
    function = section(source, r"^static char \*profile_startup_payload_v7\(.*?^\}")
    string_reader = section(read("client/linux/routervpn-gtk-product.c"), r"^static const char \*obj_string\(.*?^\}")
    assert 'profile_external_startup_dialog_v7(app)' in source
    assert 'routervpn_require_mutation_idle(app, "saving imported-node startup")' in source
    assert 'api_request("/api/profile/startup", "POST", payload' in source
    flags = subprocess.check_output(["pkg-config", "--cflags", "--libs", "json-glib-1.0"], text=True).split()
    for name, body in {"shipping": function, "wrong-owner": function.replace('json_builder_add_string_value(builder, token)', 'json_builder_add_string_value(builder, "unrelated-source")')}.items():
        if name != "shipping" and body == function:
            raise RuntimeError("GTK negative mutation did not apply")
        path, binary = directory / (name + ".c"), directory / name
        path.write_text("#include <stdlib.h>\n#include <json-glib/json-glib.h>\n" + string_reader + "\n" + body + C_TEST, encoding="utf-8")
        run(["cc", "-Wall", "-Wextra", "-Werror", str(path), "-o", str(binary), *flags])
        run([str(binary)], broken=name != "shipping")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--platform", required=True, choices=("windows", "macos", "linux"))
    parser.add_argument("--shell", default="pwsh")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="routervpn-startup-settings-") as temp:
        directory = Path(temp)
        if args.platform == "windows":
            windows(directory, args.shell)
        else:
            globals()[args.platform](directory)
    print(f"{args.platform} shipping startup serializer, captured identity and negative controls: PASS")
