#!/usr/bin/env python3
"""Execute captured native Tor editor callbacks and their actual Go importer."""
from pathlib import Path
import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

from test_desktop_amnezia_forms import block

ROOT = Path(__file__).resolve().parents[1]
SELECTIONS = ('local', 'server', 'auto') + tuple('ordinary-' + protocol for protocol in
    ('wireguard', 'amneziawg', 'socks5', 'http-connect', 'https-connect', 'shadowsocks', 'hysteria2', 'openvpn'))
SELECTIONS += tuple('plain-' + selection for selection in SELECTIONS)
CATALOG_FILES = ('tor-update-capabilities.json', 'tor-update-input-lines.json', 'tor-fixed-input-sets.json') + tuple(
    'tor-update-' + (selection + '-' if selection != 'local' else '') + suffix
    for selection in SELECTIONS for suffix in ('source-catalog.json', 'always-source-catalog.json'))

PAYLOAD_ROOT = 'TestDesktopTorBridgeUpdateFormPayload'
PAYLOAD_PACKAGE = 'router-vpn/cmd/client'
WINDOWS_EDITOR_PROGRESS = 'tor-editor-progress.log'
WINDOWS_EDITOR_CHECKS = 4186


def verify_windows_editor_progress(directory):
    """Require the fixed diagnostic sequence without admitting payload values."""
    with (directory / WINDOWS_EDITOR_PROGRESS).open('rb') as stream:
        raw = stream.read(16385)
    if len(raw) > 16384:
        raise RuntimeError('Windows Tor editor diagnostic exceeded its bounded record')
    try:
        lines = raw.decode('ascii').splitlines()
    except UnicodeDecodeError as error:
        raise RuntimeError('Windows Tor editor diagnostic contains a nonnumeric or private field') from error
    phases = [('ast-extraction', 0), ('input-controls', 0), ('wpf-initialization', 0)]
    phases += [('selection', index) for index in range(1, len(SELECTIONS) + 1)]
    phases += [('direct-cases', 0), ('window-close', 0)]
    expected = [(phase, event, selection) for phase, selection in phases for event in ('start', 'complete')]
    if len(SELECTIONS) != 22 or len(lines) != len(expected):
        raise RuntimeError('Windows Tor editor diagnostic omitted or added a phase')
    pattern = re.compile(r'RouterVPN Tor editor phase=([a-z-]+) event=(start|complete) '
                         r'selection=([0-9]{1,2}) checks=([0-9]{1,6}) '
                         r'elapsed_ms=([0-9]{1,12}) phase_ms=([0-9]{1,12})')
    prior_time, prior_checks, started = 0, 0, 0
    for line, (phase, event, selection) in zip(lines, expected):
        match = pattern.fullmatch(line)
        if match is None:
            raise RuntimeError('Windows Tor editor diagnostic contains a nonnumeric or private field')
        actual_phase, actual_event, ordinal, checks, elapsed, duration = match.groups()
        ordinal, checks, elapsed, duration = map(int, (ordinal, checks, elapsed, duration))
        if (actual_phase, actual_event, ordinal) != (phase, event, selection):
            raise RuntimeError('Windows Tor editor diagnostic changed its exact phase order')
        if elapsed < prior_time or checks < prior_checks:
            raise RuntimeError('Windows Tor editor diagnostic regressed its observations')
        if event == 'start':
            if duration != 0:
                raise RuntimeError('Windows Tor editor diagnostic invented a completed duration')
            started = elapsed
        elif duration != elapsed - started:
            raise RuntimeError('Windows Tor editor diagnostic changed its observed phase duration')
        prior_time, prior_checks = elapsed, checks
    if prior_checks != WINDOWS_EDITOR_CHECKS:
        raise RuntimeError('Windows Tor editor omitted its complete callback assertion inventory')


def payload_cases(directory, platform):
    """Bind every importer leaf to the actual Go catalog and native form outputs."""
    catalogs = {path.name for path in directory.glob('tor-update-*source-catalog.json')}
    required = {name for name in CATALOG_FILES if name.endswith('source-catalog.json')}
    if catalogs != required or len(set(SELECTIONS)) != len(SELECTIONS):
        raise RuntimeError('Tor importer selections do not match the complete Go source catalog')
    transports = json.loads((directory / 'tor-update-input-lines.json').read_text())
    if not isinstance(transports, dict) or not transports or any(
            not re.fullmatch(r'[a-z0-9][a-z0-9_-]{0,31}', name) or
            not isinstance(lines, list) or any(not isinstance(line, str) for line in lines)
            for name, lines in transports.items()):
        raise RuntimeError('Tor importer transport catalog is malformed')
    dynamic = {'tor-create-dynamic-' + transport + '-' + kill + '.json'
               for transport in transports if transport != 'obfs4'
               for kill in ('on-connect', 'always')} if platform == 'linux' else set()
    if {path.name for path in directory.glob('tor-create-dynamic-*.json')} != dynamic:
        raise RuntimeError('Tor importer omitted or added a protected Direct form payload')
    cases = [*sorted(dynamic), 'new-plain-direct']
    cases.extend('new-fixed/' + transport + '/' + str(count) + '/' + kill
                 for transport in ('obfs4', 'custom') for count in (1, 2, 8)
                 for kill in ('on-connect', 'always'))
    for selection in SELECTIONS:
        cases.append(selection + '/unchanged-saved-protection')
        cases.extend(selection + '/' + transport + '/' + kill
                     for transport in transports for kill in ('off', 'on-connect', 'always'))
    if len(set(cases)) != len(cases):
        raise RuntimeError('Tor importer expected cases contain a duplicate')
    return frozenset(PAYLOAD_ROOT + '/' + case for case in cases)


def payload_phases(expected):
    # One Windows invocation passed all 365 leaves in 34.530s; its second shell
    # exhausted the shared 60s alarm at the 13th of 22 execution selections.
    # Keep durable writes and every assertion, but give independent families
    # separate serial invocations with the original 60s test/180s outer bounds.
    phases = {name: set() for name in ('direct-and-router', 'ordinary-entry', 'plain-ordinary-entry')}
    for case in expected:
        choice = case[len(PAYLOAD_ROOT) + 1:].split('/', 1)[0]
        name = ('plain-ordinary-entry' if choice.startswith('plain-ordinary-') else
                'ordinary-entry' if choice.startswith('ordinary-') else 'direct-and-router')
        phases[name].add(case)
    result = []
    for name, cases in phases.items():
        if not cases:
            raise RuntimeError('Tor importer phase is empty: ' + name)
        choices = sorted({case[len(PAYLOAD_ROOT) + 1:].split('/', 1)[0] for case in cases})
        selector = '^' + PAYLOAD_ROOT + '$/^(' + '|'.join(re.escape(choice) for choice in choices) + ')$'
        result.append((name, selector, frozenset(cases)))
    return result


def verify_payload_verdicts(output, expected):
    required = set(expected) | {PAYLOAD_ROOT}
    ran, passed, package_passed = set(), set(), False
    for line in output.splitlines():
        try:
            event = json.loads(line)
        except (ValueError, TypeError) as error:
            raise RuntimeError('Tor importer emitted a malformed Go verdict') from error
        if not isinstance(event, dict):
            raise RuntimeError('Tor importer emitted a malformed Go verdict')
        action, test, package = event.get('Action'), event.get('Test'), event.get('Package')
        if action in ('fail', 'skip'):
            raise RuntimeError('Tor importer emitted a failed or skipped verdict')
        if package != PAYLOAD_PACKAGE:
            raise RuntimeError('Tor importer verdict belongs to a different package')
        if test is not None:
            if test not in required:
                raise RuntimeError('Tor importer executed an unexpected case: ' + str(test))
            if action == 'run':
                if test in ran or (test != PAYLOAD_ROOT and PAYLOAD_ROOT not in ran):
                    raise RuntimeError('Tor importer duplicated or reordered a run verdict')
                ran.add(test)
            elif action == 'pass':
                if test not in ran or test in passed or (test == PAYLOAD_ROOT and passed != set(expected)):
                    raise RuntimeError('Tor importer duplicated or omitted an executed case')
                passed.add(test)
            elif action not in ('output', 'pause', 'cont'):
                raise RuntimeError('Tor importer emitted an unknown test verdict')
        elif action == 'pass':
            if package_passed or passed != required:
                raise RuntimeError('Tor importer duplicated or omitted the complete package verdict')
            package_passed = True
        elif action not in ('start', 'output'):
            raise RuntimeError('Tor importer emitted an unknown package verdict')
    if ran != required or passed != required or not package_passed:
        raise RuntimeError('Tor importer omitted an executed case or final package verdict')


def run_payload_phases(directory, platform, env):
    expected = payload_cases(directory, platform)
    phases = payload_phases(expected)
    covered = set()
    for _, _, cases in phases:
        if covered.intersection(cases):
            raise RuntimeError('Tor importer phases contain duplicate cases')
        covered.update(cases)
    if covered != set(expected):
        raise RuntimeError('Tor importer phases omit expected cases')
    for name, selector, cases in phases:
        command = ['go', 'test', '-json', '-race', '-count=1', './cmd/client', '-run', selector, '-timeout=60s']
        try:
            result = subprocess.run(command, cwd=ROOT, env=env, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, text=True, encoding='utf-8', errors='replace', timeout=180)
        except subprocess.TimeoutExpired as error:
            output = error.stdout or ''
            print(output.decode('utf-8', errors='replace') if isinstance(output, bytes) else output, end='', flush=True)
            diagnostic = error.stderr or ''
            print(diagnostic.decode('utf-8', errors='replace') if isinstance(diagnostic, bytes) else diagnostic,
                  end='', file=sys.stderr, flush=True)
            raise
        # Go driver/download/compiler diagnostics are not test2json verdicts.
        # Keep them visible on their original channel for every exit status.
        if result.stderr:
            print(result.stderr, end='', file=sys.stderr, flush=True)
        try:
            if result.returncode:
                raise subprocess.CalledProcessError(result.returncode, command, output=result.stdout)
            verify_payload_verdicts(result.stdout, cases)
        except (RuntimeError, subprocess.CalledProcessError):
            print(result.stdout, end='', flush=True)
            raise
        print('Native Tor importer ' + name + ': ' + str(len(cases)) + ' exact leaves PASS', flush=True)
    print('Native Tor importer: ' + str(len(expected)) + ' distinct leaves PASS', flush=True)


def swift_source(generated):
    helpers = generated[:generated.index('private final class RouterVPNTorBridgeBuilder')]
    external = (ROOT / 'client/macos/RouterVPNMacExternalNode.swift').read_text()
    helpers += block(external, 'func externalValidateCapturedBody(') + '\n' + block(external, 'func externalCapturedBody(')
    save = block(generated, '    @objc private func save()').replace('@objc private ', '')
    methods = block(generated, '    private func selectedTransport()').replace('private ', '') + '\n' + block(generated, '    private func selectedKillSwitch()').replace('private ', '')
    methods += '\n' + block(generated, '    @objc private func updateSelectionChanged()').replace('@objc private ', '')
    capture = generated[generated.index('        let selection: [String: Any]'):generated.index('        let panel = NSPanel')]
    transports = next(line.strip().replace('private ', '') for line in generated.splitlines() if 'private let transportIDs = ' in line)
    template = (ROOT / 'client/macos/test-tor-bridge-update.swift').read_text()
    for marker, value in [('/* HELPERS */', helpers), ('/* METHODS */', methods), ('/* SAVE */', save), ('/* CAPTURE */', capture), ('/* TRANSPORTS */', transports)]:
        assert template.count(marker) == 1
        template = template.replace(marker, value)
    return template


def swift_form(directory):
    transform = (ROOT / 'client/macos/macos-tor-bridge-ui-transform.py').read_text()
    generated = transform.split("tor_class = r'''", 1)[1].split("\n'''", 1)[0]
    source, binary = directory / 'tor-form.swift', directory / 'tor-form'
    source.write_text(swift_source(generated))
    subprocess.run(['swiftc', '-swift-version', '5', '-module-cache-path', str(directory/'module-cache'), str(source), '-o', str(binary)], check=True, timeout=120)
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
        ('plain-lines', 'guard bridges.isEmpty else', 'guard true else',
         'Tor update adopted plain-lines'),
        ('direct-fixed-source', 'return (words.first == "bridge" ? words.dropFirst().first : words.first) == "obfs4"',
         '_ = words; return true', 'Direct custom set admitted dynamic bridge meek_lite'),
    )
    for name, original, replacement, witness in controls:
        assert generated.count(original) == 1, name
        negative = directory / ('negative-' + name)
        negative.mkdir()
        for filename in CATALOG_FILES: shutil.copyfile(directory / filename, negative / filename)
        changed, executable = negative / 'tor-form.swift', negative / 'tor-form'
        changed.write_text(swift_source(generated.replace(original, replacement)))
        subprocess.run(['swiftc', '-swift-version', '5', '-module-cache-path', str(directory/'module-cache'), str(changed), '-o', str(executable)], check=True, timeout=120)
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
        ('entry-fixed-bridge', '!external_path_flag_v4(profile, "multihop_enabled") &&', 'TRUE &&',
         'Rejected trial identity: ordinary-fixed-bypass'),
        ('mixed-udp', 'if (g_regex_match_simple("(*UCP)(?i)^\\\\s*(?:bridge\\\\s+)?snowflake(?:\\\\s|$)", line, 0, 0)) udp = TRUE;',
         '(void)line;', 'Rejected trial identity: ordinary-mixed-udp'),
        ('plain-lines', '(plain && bridges->len != 0) || ', '',
         'Rejected trial identity: plain-lines'),
        ('direct-fixed-source', 'fixed = kind != NULL && g_ascii_strcasecmp(kind, "obfs4") == 0;',
         '(void)kind; fixed = TRUE;', 'Rejected trial identity: fixed-mixed-meek_lite'),
        ('dynamic-runtime', 'external_path_flag_v4(capability, "supported") && external_path_flag_v4(capability, "strict_dynamic_direct_kill_switch")',
         'external_path_flag_v4(capability, "strict_dynamic_direct_kill_switch")', 'Rejected trial identity: dynamic-unverified'),
        ('dynamic-owner', 'external_path_flag_v4(capability, "supported") && external_path_flag_v4(capability, "strict_dynamic_direct_kill_switch")',
         'external_path_flag_v4(capability, "supported")', 'Rejected trial identity: direct-strict'),
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
    print('Starting actual Windows Tor editor; child timeout remains 60 seconds', flush=True)
    subprocess.run([*command, '-Output', str(directory)], check=True, timeout=60)
    verify_windows_editor_progress(directory)
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
        ('plain-lines', 'if($Plain-and$BridgeCount-ne0)', 'if($false)',
         'Tor update adopted plain-lines'),
        ('direct-fixed-source', "if($Kind-ine'obfs4'){$Fixed=$false}", 'if($false){$Fixed=$false}',
         'Direct custom set admitted dynamic bridge meek_lite'),
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
        run_payload_phases(directory, args.platform, env)
    print('Native Tor '+args.platform+' callback payloads and actual importer: PASS', flush=True)


if __name__ == '__main__': main()
