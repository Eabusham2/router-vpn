#!/usr/bin/env python3
from pathlib import Path
root=Path(__file__).resolve().parents[1]
store=(root/'android/app/src/main/java/com/eabusham/routervpn/AndroidStandardExitStore.java').read_text()
controller=(root/'android/app/src/main/java/com/eabusham/routervpn/AndroidStandardExitController.java').read_text()
direct=(root/'android/app/src/main/java/com/eabusham/routervpn/AndroidDirectStandardExitController.java').read_text()
runtime=(root/'android/app/src/main/java/com/eabusham/routervpn/AndroidStandardExitRuntime.java').read_text()
activity=(root/'android/app/src/main/java/com/eabusham/routervpn/StandardExitActivity.java').read_text()
for marker in ['"wireguard",true','"socks5",true','"http",true','"https",true','"shadowsocks",true','"hysteria2",true','"openvpn",true','standard-exits.json','Expected public exit IP must be public','AndroidOpenVPN.endpoint(e, "")','HTTPS proxy requires a valid TLS server name']:
    assert marker in store, marker
for marker in ['put("detour","entry-wg")','put("tag","custom-exit")','put("final","custom-exit")','put("listen","127.0.0.1").put("listen_port",1099)','AndroidKillSwitchPolicy.SESSION_MARKER','literal DNS server IP','"http".equals(e.protocol)||"https".equals(e.protocol)','out.put("type","http")','put("server_name",e.tlsServerName)']:
    assert marker in controller, marker
for marker in ['AndroidKillSwitchPolicy.SESSION_MARKER','put("strict_route", true)','put("server", "1.1.1.1")','put("detour", "custom-exit")','put("final", "custom-exit")','standard-direct-','AndroidOpenVPN.endpoint(e, "")','"http".equals(e.protocol) || "https".equals(e.protocol)','out.put("type", "http")','put("server_name", e.tlsServerName)']:
    assert marker in direct, marker
for marker in ['connectDirect(AndroidStandardExitStore.Entry exit','directBuilder.prepare(exit)','new Proxy(Proxy.Type.HTTP,new InetSocketAddress("127.0.0.1",1099))','proveExpectedPublicIp(exit.expectedPublicIp)','boolean stopped=!started||stopEmbeddedAndProve();','Public exit proof passed']:
    assert marker in runtime, marker
for marker in ['Connect direct external exit','Connect via Router VPN entry → external exit','HTTP CONNECT','HTTPS CONNECT + TLS','requestDirect(','runtime.connectDirect(exit,cb)','Always-on VPN plus ‘Block connections without VPN’','Other hopped external exits currently use WireGuard','TLS server name / SNI for certificate verification']:
    assert marker in activity, marker
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
