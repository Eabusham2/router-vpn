#!/usr/bin/env python3
from pathlib import Path
root=Path(__file__).resolve().parents[1]
store=(root/'android/app/src/main/java/com/eabusham/routervpn/AndroidStandardExitStore.java').read_text()
controller=(root/'android/app/src/main/java/com/eabusham/routervpn/AndroidStandardExitController.java').read_text()
direct=(root/'android/app/src/main/java/com/eabusham/routervpn/AndroidDirectStandardExitController.java').read_text()
runtime=(root/'android/app/src/main/java/com/eabusham/routervpn/AndroidStandardExitRuntime.java').read_text()
activity=(root/'android/app/src/main/java/com/eabusham/routervpn/StandardExitActivity.java').read_text()
for marker in ['"wireguard",true','"socks5",true','"shadowsocks",true','"hysteria2",true','"openvpn",false','standard-exits.json','Expected public exit IP must be public','no fake OpenVPN mode']:
    assert marker in store, marker
for marker in ['put("detour","entry-wg")','put("tag","custom-exit")','put("final","custom-exit")','put("listen","127.0.0.1").put("listen_port",1099)','AndroidKillSwitchPolicy.SESSION_MARKER','literal DNS server IP']:
    assert marker in controller, marker
for marker in ['AndroidKillSwitchPolicy.SESSION_MARKER','put("strict_route", true)','put("server", "1.1.1.1")','put("detour", "custom-exit")','put("final", "custom-exit")','standard-direct-','OpenVPN direct exit is unavailable on Android']:
    assert marker in direct, marker
for marker in ['connectDirect(AndroidStandardExitStore.Entry exit','directBuilder.prepare(exit)','new Proxy(Proxy.Type.HTTP,new InetSocketAddress("127.0.0.1",1099))','proveExpectedPublicIp(exit.expectedPublicIp)','if(started)singBox.stop()','Public exit proof passed']:
    assert marker in runtime, marker
for marker in ['Connect direct external exit','Router VPN WireGuard entry → external exit','requestDirect(','runtime.connectDirect(exit,cb)','Always-on VPN plus ‘Block connections without VPN’']:
    assert marker in activity, marker
assert 'callback.finished(true' not in runtime
print('Android custom standard-exit source contract OK')
