#!/usr/bin/env python3
"""Execute captured native Tor editor callbacks and their actual Go importer."""
from pathlib import Path
import argparse
import os
import shutil
import subprocess
import sys
import tempfile

from test_desktop_amnezia_forms import block

ROOT = Path(__file__).resolve().parents[1]
CATALOG_FILES = ('tor-update-source-catalog.json', 'tor-update-always-source-catalog.json',
                 'tor-update-server-source-catalog.json', 'tor-update-server-always-source-catalog.json',
                 'tor-update-capabilities.json', 'tor-update-input-lines.json') + tuple(
    'tor-update-ordinary-' + protocol + '-' + suffix for protocol in
    ('wireguard', 'amneziawg', 'socks5', 'http-connect', 'https-connect', 'shadowsocks', 'hysteria2', 'openvpn')
    for suffix in ('source-catalog.json', 'always-source-catalog.json'))


def swift_source(generated):
    helpers = generated[:generated.index('private final class RouterVPNTorBridgeBuilder')]
    external = (ROOT / 'client/macos/RouterVPNMacExternalNode.swift').read_text()
    helpers += block(external, 'func externalValidateCapturedBody(') + '\n' + block(external, 'func externalCapturedBody(')
    save = block(generated, '    @objc private func save()').replace('@objc private ', '')
    methods = block(generated, '    private func selectedTransport()').replace('private ', '') + '\n' + block(generated, '    private func selectedKillSwitch()').replace('private ', '')
    methods += '\n' + block(generated, '    @objc private func updateSelectionChanged()').replace('@objc private ', '')
    capture = generated[generated.index('        let selection: [String: Any]'):generated.index('        let panel = NSPanel')]
    template = (ROOT / 'client/macos/test-tor-bridge-update.swift').read_text()
    for marker, value in [('/* HELPERS */', helpers), ('/* METHODS */', methods), ('/* SAVE */', save), ('/* CAPTURE */', capture)]:
        assert template.count(marker) == 1
        template = template.replace(marker, value)
    return template


def swift_form(directory):
    transform = (ROOT / 'client/macos/macos-tor-bridge-ui-transform.py').read_text()
    generated = transform.split("tor_class = r'''", 1)[1].split("\n'''", 1)[0]
    source, binary = directory / 'tor-form.swift', directory / 'tor-form'
    source.write_text(swift_source(generated))
    subprocess.run(['swiftc', '-swift-version', '5', str(source), '-o', str(binary)], check=True, timeout=120)
    subprocess.run([str(binary), str(directory)], check=True, timeout=60)
    controls = (
        ('saved-protection',
         'killSwitchPopup.selectItem(at: ["off", "on-connect", "always"].firstIndex(of: policy) ?? -1)',
         '_ = policy; killSwitchPopup.selectItem(at: 0)',
         'Update checkbox did not load saved Always and name'),
        ('current-source',
         'try externalValidateCapturedBody(body, current: current)', '_ = current',
         'Tor update adopted selected'),
        ('captured-entry',
         'result["expected_profile_tokens"] = capture["expected_profile_tokens"]',
         'result["expected_profile_tokens"] = [id: (capture["expected_profile_tokens"] as! [String: String])[id]!]',
         'Entry/source identity dropped'),
        ('entry-fixed-bridge', ' && !throughEntry', '',
         'Tor update adopted ordinary-fixed-bypass'),
        ('mixed-udp', 'return (words.first == "bridge" ? words.dropFirst().first : words.first) == "snowflake"',
         '_ = words; return false', 'Tor update adopted ordinary-mixed-udp'),
    )
    for name, original, replacement, witness in controls:
        assert generated.count(original) == 1, name
        negative = directory / ('negative-' + name)
        negative.mkdir()
        for filename in CATALOG_FILES: shutil.copyfile(directory / filename, negative / filename)
        changed, executable = negative / 'tor-form.swift', negative / 'tor-form'
        changed.write_text(swift_source(generated.replace(original, replacement)))
        subprocess.run(['swiftc', '-swift-version', '5', str(changed), '-o', str(executable)], check=True, timeout=120)
        result = subprocess.run([str(executable), str(negative)], capture_output=True, text=True, timeout=60)
        if result.returncode == 0 or witness not in result.stdout + result.stderr:
            raise AssertionError(name + ' mutation missed its actual Swift assertion: ' + result.stdout + result.stderr)
        print('Actual Swift Tor ' + name + ' mutation: rejected at its intended assertion', flush=True)


def linux_form(directory):
    product = (ROOT / 'client/linux/routervpn-gtk-product-v4.c').read_text()
    helpers = '\n'.join(block(product, marker) for marker in (
        'static const char *external_saved_execution_v4(', 'static char *json_external_hop_body(',
        'static const char *external_path_string_v4(', 'static gboolean external_path_flag_v4(',
        'static JsonObject *external_path_object_v4('))
    helpers += '\n' + block((ROOT / 'client/linux/routervpn-gtk-product.c').read_text(), 'static JsonNode *copy_public_source_value_v24(')
    helpers += '\n' + (ROOT / 'client/linux/routervpn-external-source-v24.inc').read_text()
    template = (ROOT / 'client/linux/test-tor-bridge-update.c').read_text()
    assert template.count('/* HELPERS */') == 1
    source, binary = directory / 'tor-form.c', directory / 'tor-form'
    rendered = template.replace('/* HELPERS */', helpers)
    source.write_text(rendered)
    flags = subprocess.check_output(['pkg-config', '--cflags', '--libs', 'gtk+-3.0', 'json-glib-1.0'], text=True).split()
    subprocess.run(['cc', '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', '-Wno-unused-function',
                    '-I'+str(ROOT/'client/linux'), str(source), '-o', str(binary), *flags], check=True, timeout=120)
    subprocess.run(['xvfb-run', '-a', str(binary), str(directory)], check=True, timeout=60)
    # Compile the actual shipping callbacks with one guard changed at a time.
    # A parse/build failure is never evidence that a behavior was rejected.
    shipping = (ROOT / 'client/linux/routervpn-tor-bridge-v13.inc').read_text()
    controls = (
        ('saved-protection',
         'gboolean loaded = gtk_combo_box_set_active_id(GTK_COMBO_BOX(state->kill), policy);',
         '(void)policy; gboolean loaded = gtk_combo_box_set_active_id(GTK_COMBO_BOX(state->kill), "off");',
         'Update disabled saved Always protection before any user edit'),
        ('current-source',
         'external_captured_body_v24(payload, state->opened, current, validation_error)',
         'external_captured_body_v24(payload, state->opened, current != NULL ? NULL : current, validation_error)',
         'cancelled/rejected modal escaped its owned callback'),
        ('opened-catalog',
         'state.opened = displayed != NULL ? copy_public_source_value_v24(displayed) : NULL;',
         'state.opened = displayed != NULL ? json_node_copy(displayed) : NULL;',
         'cancelled/rejected modal escaped its owned callback'),
        ('entry-fixed-bridge', ' && !external_path_flag_v4(profile, "multihop_enabled")', '',
         'Rejected trial identity: ordinary-fixed-bypass'),
        ('mixed-udp', 'if (g_regex_match_simple("(*UCP)(?i)^\\\\s*(?:bridge\\\\s+)?snowflake(?:\\\\s|$)", line, 0, 0)) udp = TRUE;',
         '(void)line;', 'Rejected trial identity: ordinary-mixed-udp'),
    )
    include = '#include "routervpn-tor-bridge-v13.inc"'
    assert rendered.count(include) == 1
    for name, original, replacement, witness in controls:
        assert shipping.count(original) == 1, name + ' must change exactly one shipping callback guard'
        negative = directory / ('negative-' + name)
        negative.mkdir()
        for filename in CATALOG_FILES:
            shutil.copyfile(directory / filename, negative / filename)
        changed_source, changed_binary = negative / 'tor-form.c', negative / 'tor-form'
        changed_source.write_text(rendered.replace(include, shipping.replace(original, replacement)))
        subprocess.run(['cc', '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', '-Wno-unused-function',
                        '-I'+str(ROOT/'client/linux'), str(changed_source), '-o', str(changed_binary), *flags], check=True, timeout=120)
        rejected = subprocess.run(['xvfb-run', '-a', str(changed_binary), str(negative)],
                                  capture_output=True, text=True, timeout=60)
        # Debian's xvfb-run merges the child stderr into stdout while retaining
        # its exit status; require both the failing status and precise witness.
        output = rejected.stdout + rejected.stderr
        (negative / 'result.log').write_text(output)
        if rejected.returncode == 0 or witness not in output:
            raise AssertionError(name + ' mutation missed its actual GTK assertion: ' + output)
        print('Actual GTK Tor ' + name + ' mutation: rejected at its intended assertion', flush=True)


def windows_form(directory, shell):
    apartment = ['-STA'] if sys.platform == 'win32' else []
    command = [shell, *apartment, '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File',
               str(ROOT/'client/test-windows-tor-bridge-update.ps1')]
    subprocess.run([*command, '-Output', str(directory)], check=True, timeout=60)
    source = (ROOT / 'client/RouterVPN-Windows-TorBridge.ps1').read_text()
    controls = (
        ('saved-protection', "$SavedPolicy=[string](ExternalPublicValue $SavedProfile 'kill_switch_policy')", "$SavedPolicy='off'",
         'Update checkbox did not load the saved Always policy and name'),
        ('current-source', '$Capture=NewUnifiedExternalCapturedBody @{profile_id=$ID} $Opened $Current',
         '$Capture=NewUnifiedExternalCapturedBody @{profile_id=$ID} $Opened $null', 'Tor update adopted selected'),
        ('opened-catalog', '$Displayed|ConvertTo-Json -Depth 32|ConvertFrom-Json', '$Displayed', 'Tor update adopted display-mutated'),
        ('entry-fixed-bridge', "-and(-not$Update-or(ExternalPublicValue $Profile 'multihop_enabled' $false) -cne $true)", '',
         'Tor update adopted ordinary-fixed-bypass'),
        ('mixed-udp', "if(([string]$Line)-match'^\\s*(?:bridge\\s+)?snowflake(?:\\s|$)')", 'if($false)',
         'Tor update adopted ordinary-mixed-udp'),
    )
    for name, original, replacement, witness in controls:
        assert source.count(original) == 1, name
        negative = directory / ('negative-' + name)
        (negative / 'client').mkdir(parents=True)
        for filename in CATALOG_FILES: shutil.copyfile(directory / filename, negative / filename)
        (negative / 'client/RouterVPN-Windows-TorBridge.ps1').write_text(source.replace(original, replacement), encoding='utf-8-sig')
        result = subprocess.run([*command, '-Root', str(negative), '-Output', str(negative)],
                                capture_output=True, text=True, timeout=60)
        if result.returncode == 0 or witness not in result.stdout + result.stderr:
            raise AssertionError(name + ' mutation missed its actual Windows assertion: ' + result.stdout + result.stderr)
        print('Actual Windows Tor ' + name + ' mutation: rejected at its intended assertion', flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--platform', choices=['linux', 'darwin', 'windows'], default='windows' if sys.platform == 'win32' else sys.platform)
    parser.add_argument('--shell', default='powershell.exe' if sys.platform == 'win32' else 'pwsh')
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='routervpn-tor-forms-') as temporary:
        directory = Path(temporary)
        env = dict(os.environ, ROUTERVPN_TOR_FORM_PAYLOADS=str(directory))
        subprocess.run(['go', 'test', '-count=1', './cmd/client', '-run', '^TestDesktopTorBridgeUpdateFormCatalog$', '-timeout=60s'], cwd=ROOT, env=env, check=True, timeout=180)
        if args.platform == 'linux': linux_form(directory)
        elif args.platform == 'darwin': swift_form(directory)
        else: windows_form(directory, args.shell)
        subprocess.run(['go', 'test', '-race', '-count=1', './cmd/client', '-run', '^TestDesktopTorBridgeUpdateFormPayload$', '-timeout=60s'], cwd=ROOT, env=env, check=True, timeout=180)
    print('Native Tor '+args.platform+' callback payloads and actual importer: PASS', flush=True)


if __name__ == '__main__': main()
