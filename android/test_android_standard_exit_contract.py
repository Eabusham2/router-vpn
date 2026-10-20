#!/usr/bin/env python3
from pathlib import Path
root=Path(__file__).resolve().parents[1]
store=(root/'android/app/src/main/java/com/eabusham/routervpn/AndroidStandardExitStore.java').read_text()
controller=(root/'android/app/src/main/java/com/eabusham/routervpn/AndroidStandardExitController.java').read_text()
direct=(root/'android/app/src/main/java/com/eabusham/routervpn/AndroidDirectStandardExitController.java').read_text()
runtime=(root/'android/app/src/main/java/com/eabusham/routervpn/AndroidStandardExitRuntime.java').read_text()
activity=(root/'android/app/src/main/java/com/eabusham/routervpn/StandardExitActivity.java').read_text()
policy=(root/'android/app/src/main/java/com/eabusham/routervpn/AndroidExternalPolicy.java').read_text()
entry=(root/'android/app/src/main/java/com/eabusham/routervpn/AndroidExternalEntry.java').read_text()
session=(root/'android/app/src/main/java/com/eabusham/routervpn/AndroidExternalSession.java').read_text()
service=(root/'android/app/src/main/java/com/eabusham/routervpn/LayeredVpnService.java').read_text()
for marker in ['"wireguard",true','"socks5",true','"http",true','"https",true','"shadowsocks",true','"hysteria2",true','"openvpn",true','standard-exits.json','Expected public exit IP must be public','AndroidOpenVPN.endpoint(e, "")','HTTPS proxy requires a valid TLS server name']:
    assert marker in store, marker
for marker in ['AndroidStandardExitStore.validate(exit)', 'AndroidExternalPolicy.supports(exit.protocol)',
               'AndroidExternalPolicy.prepare(context, entryBundle, exit, entryMode)',
               'The selected external protocol has no captured native policy owner.']:
    assert marker in controller, marker
for marker in ['AndroidStandardExitStore.validate(exit)', 'AndroidExternalPolicy.supports(exit.protocol)',
               'AndroidExternalPolicy.prepare(context, null, exit, "external")',
               'AndroidOpenVPN.endpoint(e, "")','"http".equals(e.protocol) || "https".equals(e.protocol)',
               'out.put("type", "http")','put("server_name", e.tlsServerName)']:
    assert marker in direct, marker
for marker in ['"wireguard", "socks5", "http", "https", "shadowsocks", "hysteria2", "openvpn"',
               'Libbox.routerCompileExternalPolicy(source, capture)',
               '"openvpn".equals(exit.protocol)) endpoints.put(transport)',
               'put("openvpn", new JSONObject().put("config", exit.openVPNConfig)',
               'put("username", exit.username).put("password", exit.password)',
               'AndroidExternalEntry.prepare(context,entryFile,entry,entryMode)',
               'capture.put("predecessor_config",captured.config)',
               'put("strict_route", true)', 'put("final", "custom-exit")',
               'AndroidKillSwitchPolicy.SESSION_MARKER', 'standard-direct-',
               'policy.remove("effective_mtu")', 'Libbox.checkConfig(compiled.config)']:
    assert marker in policy, marker
for marker in ['connectDirect(AndroidStandardExitStore.Entry exit','directBuilder.prepare(exit)',
               'if(!tor&&!policy)throw', 'singBox.startExternal(session,capturedHome.sessionId)',
               'capturedExternalExit(capturedHome)',
               'AndroidHomeStateStore.connectedPolicyExternal(context,capturedHome,observed)',
               'LayeredVpnService.externalExitIP(externalNativeSession,externalID)',
               'boolean stopped=!started||stopEmbeddedAndProve();',
               'Captured entry, selected DNS and public exit proof passed']:
    assert marker in runtime, marker
for marker in ['Connect direct external exit','Connect via Router VPN entry → external exit','HTTP CONNECT','HTTPS CONNECT + TLS','requestDirect(','runtime.connectDirect(exit,cb)','Always-on VPN plus ‘Block connections without VPN’','Exact Router VPN entry mode','TLS server name / SNI for certificate verification',
               'OpenVPN preserves its complete saved remote list and inline TLS settings',
               'entry.policy=AndroidExternalPolicy.editorPolicy(null)',
               'dialog.dismiss();showExternalPolicyForm(entry)']:
    assert marker in activity, marker
# The previous WG-only builders and localhost public-IP listener could bypass
# the selected DNS and complete entry proof. Every accepted non-Tor protocol
# now reaches the one captured policy/session adapter instead.
for text in (controller, direct, runtime):
    for retired in ('proveExpectedPublicIp', '1099', '"1.1.1.1"', 'buildConfig('):
        assert retired not in text, f'retired external fallback returned: {retired}'
assert 'WireGuard entry path' not in activity
for marker in ('RouterExternalProofRequest', 'routerExternalCreateProof(', 'dns_proven', 'entry_proven'):
    assert marker in session, marker
for marker in ('EXTRA_HOME_SESSION_ID', 'externalSession', 'externalExitIP(', 'failedPolicyExternal('):
    assert marker in service, marker
for case in ('test_android_external_entries.py', 'test_android_external_policy.py',
             'test_android_external_session.py', 'test_android_runtime_teardown.py'):
    assert (root/'android'/case).is_file(), f'executable external-policy coverage missing: {case}'
# A stop request is not teardown proof. Both cancellation and failure must keep
# ownership until the embedded engine reports a terminal state.
assert runtime.count("boolean stopped=!started||stopEmbeddedAndProve();") == 2
for marker in (
    "teardownInProgress=!stopped;",
    "if(sessionStarted&&!suppressHome&&sameHomeOwner(tor,capturedHome))",
    "else if(stopped)",
    "runtime ownership retained",
    "if(!stopped)throw new IllegalStateException",
):
    assert marker in runtime, f"standard-exit teardown ownership missing: {marker}"
stop = runtime.split("private boolean stopEmbeddedAndProve(){", 1)[1].split("private static boolean terminal", 1)[0]
for marker in (
    "boolean interrupted=Thread.interrupted();",
    "singBox.stop();",
    "STOP_TIMEOUT_MS",
    "if(terminal(singBox.getState()))return true;",
    "return terminal(singBox.getState());",
    "finally{if(interrupted)Thread.currentThread().interrupt();}",
):
    assert marker in stop, f"standard-exit teardown proof missing: {marker}"
terminal = runtime.split("private static boolean terminal", 1)[1].split("private static boolean runtimeBusy", 1)[0]
assert 'if(state==null)return false;' in terminal
assert 'return "DOWN".equals(normalized)||"FAILED".equals(normalized)||"REVOKED".equals(normalized);' in terminal
assert 'callback.finished(true' not in runtime
# Tor uses the same private store and custom-exit owner, with its complete
# selected predecessor and native proof handle. It has no fabricated fixed IP.
for marker in ('"tor",true', '"tor-bridge",true', 'AndroidTorProfile.validate(e)',
               'tor_policy', 'tor_bridge'):
    assert marker in store, f'Tor store capability or policy missing: {marker}'
assert 'AndroidTorProfile.prepare(context, entryBundle, exit, entryMode)' in controller
assert 'AndroidTorProfile.prepare(context, null, exit, "external")' in direct
for marker in ('AndroidStandardExitStore.copy(exit)', 'capturedTorExit(capturedHome)',
               'LayeredVpnService.torExitIP(torNativeSession,torExternalID)',
               'AndroidHomeStateStore.connectedTorExternal(context,capturedHome,observed)'):
    assert marker in runtime, f'Tor exact-owner adoption missing: {marker}'
for marker in ('showTorForm(', '"Tor with bridges"', '"Snowflake"', '"WebTunnel"',
               'pendingEntryDigest', 'pendingExitDigest', 'bridges.setSaveEnabled(false)',
               'dialog.setOnDismissListener(ignored->bridges.setText(""))',
               'Tor carries TCP; UDP and DoH3 DNS are rejected'):
    assert marker in activity, f'Tor form or captured permission input missing: {marker}'
print('Android custom standard-exit source contract OK')
