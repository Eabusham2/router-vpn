#!/usr/bin/env python3
from pathlib import Path
root=Path(__file__).resolve().parents[1]
store=(root/'android/app/src/main/java/com/eabusham/routervpn/AndroidStandardExitStore.java').read_text()
controller=(root/'android/app/src/main/java/com/eabusham/routervpn/AndroidStandardExitController.java').read_text()
runtime=(root/'android/app/src/main/java/com/eabusham/routervpn/AndroidStandardExitRuntime.java').read_text()
for marker in ['"wireguard",true','"socks5",true','"shadowsocks",true','"hysteria2",true','"openvpn",false','standard-exits.json','Expected public exit IP must be public','no fake OpenVPN mode']:
    assert marker in store, marker
for marker in ['put("detour","entry-wg")','put("tag","custom-exit")','put("final","custom-exit")','put("listen","127.0.0.1").put("listen_port",1099)','AndroidKillSwitchPolicy.SESSION_MARKER','literal DNS server IP']:
    assert marker in controller, marker
for marker in ['new Proxy(Proxy.Type.HTTP,new InetSocketAddress("127.0.0.1",1099))','proveExpectedPublicIp(exit.expectedPublicIp)','if(started)singBox.stop()','Public exit proof passed']:
    assert marker in runtime, marker
assert 'callback.finished(true' not in runtime
print('Android custom standard-exit source contract OK')
