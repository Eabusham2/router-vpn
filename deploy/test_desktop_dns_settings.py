#!/usr/bin/env python3
"""Execute shipping DNS serializers with exact displayed-node and secret-copy negatives."""
from __future__ import annotations

import argparse
import json
import xml.etree.ElementTree as ET
from pathlib import Path
import subprocess
import tempfile

from test_desktop_startup_settings import ROOT, read, run, section, windows_adapter_import


# Match the six requested secondary addresses independently of each native menu.
SECONDARY = {
    "cf4b": ("1.0.0.1", "cloudflare-dns.com"), "cf6b": ("2606:4700:4700::1001", "cloudflare-dns.com"),
    "g4b": ("8.8.4.4", "dns.google"), "g6b": ("2001:4860:4860::8844", "dns.google"),
    "q4b": ("149.112.112.112", "dns.quad9.net"), "q6b": ("2620:fe::9", "dns.quad9.net"),
}


PS_TEST = r'''
$ErrorActionPreference='Stop'
$captured=[pscustomobject]@{profile_id='node "quoted"';profile_token='captured-source';password='never-copy'}
$fields=@{mode='home';protocol='https';host='192.168.50.133';port=8443;server_name='home.example';path='/owned-query';password='never-copy'}
$body=New-RouterVPNDNSPolicyPayload -Captured $captured -DisplayedProfileID 'node "quoted"' -Fields $fields
$copy=$body|ConvertTo-Json -Compress|ConvertFrom-Json
if((@($copy.PSObject.Properties.Name|Sort-Object)-join ',') -cne 'host,mode,path,port,profile_id,profile_token,protocol,server_name'){throw 'Private or unrelated fields copied'}
if($copy.profile_id -cne 'node "quoted"' -or $copy.profile_token -cne 'captured-source'){throw 'Lost captured source identity'}
if($copy.mode -cne 'home' -or $copy.protocol -cne 'https' -or $copy.port -ne 8443 -or $copy.host -cne '192.168.50.133' -or $copy.server_name -cne 'home.example' -or $copy.path -cne '/owned-query'){throw 'Selected DNS parameters changed'}
foreach($displayed in @('','replacement','NODE "quoted"')){
    $rejected=$false
    try{New-RouterVPNDNSPolicyPayload -Captured $captured -DisplayedProfileID $displayed -Fields $fields}catch{$rejected=$true}
    if(-not$rejected){throw 'Adopted a replacement displayed node'}
}
$captured.profile_token='';$rejected=$false
try{New-RouterVPNDNSPolicyPayload -Captured $captured -DisplayedProfileID 'node "quoted"' -Fields $fields}catch{$rejected=$true}
if(-not$rejected){throw 'Missing capture token accepted'}
'''


def windows(directory, shell):
    source = read("client/RouterVPN-Windows-Product-v2.ps1")
    function = section(source, r"^function New-RouterVPNDNSPolicyPayload \{.*?^\}")
    assert "-Captured $script:DnsPolicyCapture -DisplayedProfileID ([string]$RouterCombo.SelectedValue)" in source
    refresh = section(source, r"^function RefreshDnsPolicy\{.*?^\}")
    assert refresh.index("$ExpectedProfileID=[string]$RouterCombo.SelectedValue") < refresh.index("$Policy=Api")
    assert "$RouterCombo.SelectedValue -cne $ExpectedProfileID" in refresh
    assert "$script:DnsPolicyCapture=$null" in refresh
    for value in ("tls", "https", "h3"):
        assert f'Tag="{value}"' in source
    menu = ET.fromstring(section(source, r'<ComboBox Name="DnsPresetCombo".*?</ComboBox>'))
    select = section(source, r'\$DnsPresetCombo\.Add_SelectionChanged\(\{.*?\}\);')[len('$DnsPresetCombo.Add_SelectionChanged({'):-3]
    choices = {item.get('Tag'): item.get('Content') for item in menu}
    assert len(choices) == 13
    test = ["$ErrorActionPreference='Stop'", "Set-StrictMode -Version Latest", "function ComboTag($item,$fallback){ $item.Tag }",
            "$DnsHostBox=[pscustomobject]@{Text=''}", "$DnsServerBox=[pscustomobject]@{Text=''}"]
    for tag, (address, server) in SECONDARY.items():
        assert address in choices[tag] and 'secondary' in choices[tag].lower()
        test += ["$DnsPresetCombo=[pscustomobject]@{Tag='" + tag + "'}", select,
                 f"if($DnsHostBox.Text -cne '{address}' -or $DnsServerBox.Text -cne '{server}'){{throw 'Wrong preset {tag}'}}"]
    preset_test = directory / "presets.ps1"
    preset_test.write_text("\n".join(test), encoding="utf-8-sig")
    run([shell, "-NoProfile", "-File", str(preset_test)])
    parser = directory / "parse.ps1"
    parser.write_text(r'''param([string]$Source)
$tokens=$null;$errors=$null
$text=Get-Content -LiteralPath $Source -Raw -Encoding UTF8
[void][System.Management.Automation.Language.Parser]::ParseInput($text,[ref]$tokens,[ref]$errors)
if($errors.Count){throw ($errors.Message -join '; ')}
''', encoding="utf-8-sig")
    run([shell, "-NoProfile", "-File", str(parser), "-Source", str(ROOT / "client/RouterVPN-Windows-Product-v2.ps1")])
    # The shipping loader decodes UTF-8 explicitly, including under PS 5.1.
    # Keep parsing the complete source, and prove a real syntax defect fails.
    malformed = directory / "malformed-product.ps1"
    malformed.write_text(source + "\nfunction RouterVPNBrokenSyntax {\n", encoding="utf-8")
    run([shell, "-NoProfile", "-File", str(parser), "-Source", str(malformed)], broken=True)
    variants = {
        "shipping": function,
        "replacement": function.replace("[string]$Captured.profile_id -cne $DisplayedProfileID", "$false"),
        "revision": function.replace("profile_token=[string]$Captured.profile_token", "profile_token='unrelated-source'"),
        "private": function.replace("@('mode','protocol','host','port','server_name','path')", "@('mode','protocol','host','port','server_name','path','password')"),
    }
    for name, body in variants.items():
        if name != "shipping" and body == function:
            raise RuntimeError("PowerShell DNS negative did not apply: " + name)
        path = directory / (name + ".ps1")
        path.write_text(windows_adapter_import() + body + PS_TEST, encoding="utf-8-sig")
        run([shell, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(path)], broken=name != "shipping")


SWIFT_TEST = r'''
func check(_ value: Bool, _ message: String) { if !value { fatalError(message) } }
let captured: [String: Any] = ["profile_id":"node \"quoted\"", "profile_token":"captured-source", "password":"never-copy"]
let fields: [String: Any] = ["mode":"home", "protocol":"https", "host":"192.168.50.133", "port":8443, "server_name":"home.example", "path":"/owned-query", "password":"never-copy"]
let body = try productDNSPolicyBody(captured: captured, displayedProfileID: "node \"quoted\"", fields: fields)
let raw = try JSONSerialization.data(withJSONObject: body)
let copy = try JSONSerialization.jsonObject(with: raw) as! [String: Any]
check(Set(copy.keys) == Set(["profile_id", "profile_token", "mode", "protocol", "host", "port", "server_name", "path"]), "copied private/unrelated data")
check(copy["profile_id"] as? String == "node \"quoted\"" && copy["profile_token"] as? String == "captured-source", "lost captured source")
check(copy["mode"] as? String == "home" && copy["protocol"] as? String == "https" && copy["host"] as? String == "192.168.50.133" && copy["port"] as? Int == 8443 && copy["server_name"] as? String == "home.example" && copy["path"] as? String == "/owned-query", "DNS parameters changed")
for displayed in ["", "replacement", "NODE \"quoted\""] {
    var rejected = false
    do { _ = try productDNSPolicyBody(captured: captured, displayedProfileID: displayed, fields: fields) } catch { rejected = true }
    check(rejected, "adopted a replacement displayed node")
}
var rejected = false
do { _ = try productDNSPolicyBody(captured: nil, displayedProfileID: "node \"quoted\"", fields: fields) } catch { rejected = true }
check(rejected, "missing capture accepted")
for value: Any in ["not-a-number", -1, 65536] {
    var changed = fields; changed["port"] = value; rejected = false
    do { _ = try productDNSPolicyBody(captured: captured, displayedProfileID: "node \"quoted\"", fields: changed) } catch { rejected = true }
    check(rejected, "invalid port became the transport default")
}
'''


def macos(directory):
    source = read("client/macos/RouterVPNMacProduct.swift")
    function = section(source, r"^func productDNSPolicyBody\(.*?^\}")
    callback = section(source, r"^    @objc func saveDNS\(\).*?^    \}")
    assert callback.index("let captured = dnsPolicyCapture") < callback.index("asyncAction")
    assert callback.index("let body = try productDNSPolicyBody") < callback.index("asyncAction")
    refresh = section(source, r"^    func refreshDNSPolicy\(.*?^    \}")
    assert "self.dnsPolicyGeneration == generation" in refresh
    assert "self.routerPopup.selectedItem?.representedObject as? String == selected" in refresh
    assert "dnsPolicyCapture = nil" in refresh
    assert 'let dnsProtocolIDs = ["udp", "tcp", "tls", "https", "h3"]' in source
    run(["swiftc", "-frontend", "-parse", str(ROOT / "client/macos/RouterVPNMacProduct.swift")])
    table = section(source, r"^    private let dnsPresets:.*?^    \]")
    select = section(source, r"^    @objc func dnsPresetChanged\(\).*?^    \}").replace("@objc ", "")
    menu = section(source, r'dnsPresetPopup.addItems\(withTitles: .*?\);')[:-1]
    expected = "[" + ",".join(f'("{address}", "{server}")' for address, server in SECONDARY.values()) + "]"
    preset_test = directory / "presets.swift"
    preset_test.write_text(
        'class Popup { var titles:[String]=[];var indexOfSelectedItem=0;func addItems(withTitles values:[String]){titles=values} }\n'
        'class Field {var stringValue=""}\nclass Editor {let dnsPresetPopup=Popup(), dnsHostField=Field(), dnsServerNameField=Field()\n'
        + table + "\n" + select + "\nfunc open(){" + menu + "} }\nlet editor=Editor();editor.open()\n"
        f'for (address,server) in {expected} {{\n'
        'let rows=editor.dnsPresetPopup.titles.enumerated().filter{$0.element.lowercased().contains("secondary") && $0.element.hasSuffix(" — "+address)}\n'
        'precondition(rows.count == 1);editor.dnsPresetPopup.indexOfSelectedItem=rows[0].offset;editor.dnsPresetChanged()\n'
        'precondition(editor.dnsHostField.stringValue==address && editor.dnsServerNameField.stringValue==server) }')
    run(["swiftc", "-swift-version", "6", str(preset_test), "-o", str(directory / "preset-test")])
    run([str(directory / "preset-test")])
    variants = {
        "shipping": function,
        "replacement": function.replace("profileID == displayedProfileID", "true"),
        "revision": function.replace('"profile_token": token', '"profile_token": "unrelated-source"'),
        "private": function.replace('["mode", "protocol", "host", "port", "server_name", "path"]', '["mode", "protocol", "host", "port", "server_name", "path", "password"]'),
    }
    for name, body in variants.items():
        if name != "shipping" and body == function:
            raise RuntimeError("Swift DNS negative did not apply: " + name)
        path, binary = directory / (name + ".swift"), directory / name
        path.write_text("import Foundation\n" + body + SWIFT_TEST, encoding="utf-8")
        run(["swiftc", "-swift-version", "6", "-module-cache-path", str(directory / "swift-module-cache"), str(path), "-o", str(binary)])
        run([str(binary)], broken=name != "shipping")


C_TEST = r'''
static void check(gboolean value, const char *message) { if (!value) { g_printerr("%s\n",message); exit(1); } }
int main(void) {
    JsonObject *capture=json_object_new();
    json_object_set_string_member(capture,"profile_id","node \"quoted\"");
    json_object_set_string_member(capture,"profile_token","captured-source");
    json_object_set_string_member(capture,"password","never-copy");
    char *raw=dns_policy_payload_v5(capture,"node \"quoted\"","home","https","192.168.50.133","8443","home.example","/owned-query");
    check(raw!=NULL,"payload missing");
    JsonParser *parser=json_parser_new();check(json_parser_load_from_data(parser,raw,-1,NULL),"bad JSON");
    JsonObject *body=json_node_get_object(json_parser_get_root(parser));
    check(json_object_get_size(body)==8 && !json_object_has_member(body,"password"),"copied private/unrelated data");
    check(g_strcmp0(obj_string(body,"profile_id"),"node \"quoted\"")==0 && g_strcmp0(obj_string(body,"profile_token"),"captured-source")==0,"lost captured owner");
    check(g_strcmp0(obj_string(body,"mode"),"home")==0 && g_strcmp0(obj_string(body,"protocol"),"https")==0 && g_strcmp0(obj_string(body,"host"),"192.168.50.133")==0 && json_object_get_int_member(body,"port")==8443 && g_strcmp0(obj_string(body,"server_name"),"home.example")==0 && g_strcmp0(obj_string(body,"path"),"/owned-query")==0,"DNS parameters changed");
    g_free(raw);g_object_unref(parser);
    const char *bad_ids[]={NULL,"","replacement","NODE \"quoted\""};
    for(guint i=0;i<G_N_ELEMENTS(bad_ids);i++) check(dns_policy_payload_v5(capture,bad_ids[i],"doh","https","9.9.9.9","443","dns.quad9.net","/dns-query")==NULL,"replacement selection accepted");
    const char *bad_ports[]={"wrong","53junk","-1","65536","99999999999999999999999999"};
    for(guint i=0;i<G_N_ELEMENTS(bad_ports);i++) check(dns_policy_payload_v5(capture,"node \"quoted\"","doh","https","9.9.9.9",bad_ports[i],"dns.quad9.net","/dns-query")==NULL,"invalid port became a default");
    json_object_remove_member(capture,"profile_token");
    check(dns_policy_payload_v5(capture,"node \"quoted\"","doh","https","9.9.9.9","443","dns.quad9.net","/dns-query")==NULL,"missing source revision accepted");
    json_object_unref(capture);return 0;
}
'''


def linux(directory):
    source = read("client/linux/routervpn-gtk-product-v5.c")
    function = section(source, r"^static char \*dns_policy_payload_v5\(.*?^\}")
    string_reader = section(read("client/linux/routervpn-gtk-product.c"), r"^static const char \*obj_string\(.*?^\}")
    callback = section(source, r"^static void on_save_dns_v5\(.*?^\}")
    assert "dns_policy_payload_v5(captured, active_router_id(app)" in callback
    assert 'api_request("/api/dns/policy", "POST", payload' in callback
    refresh = section(source, r"^static void refresh_dns_page_v5\(.*?^\}")
    assert 'g_strcmp0(active_router_id(app), expected) != 0' in refresh
    assert 'g_object_set_data(G_OBJECT(app->window), "router-vpn-dns-capture-v5", NULL)' in refresh
    flags = subprocess.check_output(["pkg-config", "--cflags", "--libs", "json-glib-1.0"], text=True).split()
    table = section(source, r'^static const struct \{ const char \*id, \*label, \*host, \*server; \} dns_presets_v5.*?^\};')
    select = section(source, r'^static void on_dns_preset_v5\(.*?^\}')
    assert 'gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(preset), dns_presets_v5[i].id, label)' in source
    rows = ",\n".join("{" + ",".join(map(json.dumps, (key, *value))) + "}" for key, value in SECONDARY.items())
    preset_test = directory / "presets.c"
    preset_test.write_text(
        '#include <glib-object.h>\n#include <string.h>\ntypedef const char GtkComboBox; typedef const char *GtkWidget; typedef struct {GObject *window;} App;\n'
        '#define gtk_combo_box_get_active_id(id) (id)\nstatic void dns_set_text_v5(GtkWidget *widget,const char *text){ *widget=text; }\n'
        + table + "\n" + select + '\nint main(void){ App app={g_object_new(G_TYPE_OBJECT,NULL)};GtkWidget host="",server="";\n'
        'g_object_set_data(app.window,"router-vpn-dns-host-v5",&host);g_object_set_data(app.window,"router-vpn-dns-server-v5",&server);\n'
        'const char *rows[][3]={' + rows + '};for (guint i=0;i<G_N_ELEMENTS(rows);i++){on_dns_preset_v5(rows[i][0],&app);'
        'if(strcmp(host,rows[i][1]) || strcmp(server,rows[i][2])) return 1;} g_object_unref(app.window);return 0;}')
    run(["cc", "-Wall", "-Wextra", "-Werror", str(preset_test), "-o", str(directory / "preset-test"), *flags])
    run([str(directory / "preset-test")])
    variants = {
        "shipping": function,
        "replacement": function.replace("strcmp(profile_id, displayed_id) != 0", "FALSE"),
        "revision": function.replace("json_builder_add_string_value(builder, token)", 'json_builder_add_string_value(builder, "unrelated-source")'),
    }
    for name, body in variants.items():
        if name != "shipping" and body == function:
            raise RuntimeError("GTK DNS negative did not apply: " + name)
        path, binary = directory / (name + ".c"), directory / name
        path.write_text("#include <stdlib.h>\n#include <string.h>\n#include <json-glib/json-glib.h>\n" + string_reader + "\n" + body + C_TEST, encoding="utf-8")
        run(["cc", "-Wall", "-Wextra", "-Werror", str(path), "-o", str(binary), *flags])
        run([str(binary)], broken=name != "shipping")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--platform", required=True, choices=("windows", "macos", "linux"))
    parser.add_argument("--shell", default="pwsh")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="routervpn-dns-settings-") as temp:
        directory = Path(temp)
        if args.platform == "windows":
            windows(directory, args.shell)
        else:
            globals()[args.platform](directory)
    print(f"{args.platform} shipping DNS editor, captured identity, exact parameters and negative controls: PASS")
