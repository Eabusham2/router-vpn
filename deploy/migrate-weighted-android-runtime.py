#!/usr/bin/env python3
from pathlib import Path

p = Path(__file__).resolve().with_name("weighted-release-audit.py")
t = p.read_text(encoding="utf-8")

replacements = {
'''    Gate("Android raw WG/AWG native runtime", 3.0, lambda: all_markers("android/app/src/main/java/com/eabusham/routervpn/NativeWireGuardController.java", "GoBackend", "State.UP") and all_markers("android/app/src/main/java/com/eabusham/routervpn/NativeAmneziaWGController.java", "org.amnezia.awg.backend.GoBackend", "State.UP")),''':
'''    Gate("Android raw WG/AWG native runtime", 3.0, lambda: all_markers("android/app/src/main/java/com/eabusham/routervpn/NativeWireGuardController.java", "GoBackend", "State.UP", "AndroidNativeProfilePolicy.patchWireGuardLikeConfig", "AndroidPathProbe.prove(privateBundle, 8000)", "recoverAfterNetworkChange", "network-transition recovery failed closed") and all_markers("android/app/src/main/java/com/eabusham/routervpn/NativeAmneziaWGController.java", "org.amnezia.awg.backend.GoBackend", "State.UP", "AndroidNativeProfilePolicy.patchWireGuardLikeConfig", "AndroidPathProbe.prove(privateBundle, 8000)", "recoverAfterNetworkChange", "network-transition recovery failed closed")),''',
'''    Gate("Android embedded layered AUTO/SMART/CUSTOM", 3.0, lambda: all_markers("android/app/src/main/java/com/eabusham/routervpn/AndroidModeOrchestrator.java", "AndroidPathProbe.prove", "SMART AUTO") and exists("android/app/src/main/java/com/eabusham/routervpn/LayeredVpnService.java")),''':
'''    Gate("Android embedded libbox/Xray AUTO/SMART/CUSTOM/ALL", 3.0, lambda: all_markers("android/app/src/main/java/com/eabusham/routervpn/AndroidModeOrchestrator.java", "AndroidPathProbe.prove", "SMART AUTO", "void all(File bundle,Callback cb)", "protectionRank", "ALL failed closed because no Android-native branch passed selected-node path proof", "Composite desktop MAX chains remain separate and are never faked on Android") and all_markers("android/app/src/main/java/com/eabusham/routervpn/NativeXrayController.java", "isCompositeProfile", "cannot be represented truthfully by native Xray alone") and exists("android/app/src/main/java/com/eabusham/routervpn/LayeredVpnService.java") and exists("android/app/src/main/java/com/eabusham/routervpn/XrayVpnService.java")),''',
'''    Gate("Android strict lockdown and transitions", 2.0, lambda: all_markers("android/app/src/main/java/com/eabusham/routervpn/LayeredVpnService.java", "isAlwaysOn()", "isLockdownEnabled()", "resetNetwork", "updateDefaultInterface")),''':
'''    Gate("Android strict lockdown and transitions", 2.0, lambda: all_markers("android/app/src/main/java/com/eabusham/routervpn/LayeredVpnService.java", "isAlwaysOn()", "isLockdownEnabled()", "resetNetwork", "updateDefaultInterface") and all_markers("android/app/src/main/java/com/eabusham/routervpn/XrayVpnService.java", "isAlwaysOn()", "isLockdownEnabled()", "registerDialerController", "restartAfterNetworkChange", "AndroidPathProbe.prove(activeBundle")),''',
'''    Gate("Android real narrow multihop + multi-node store", 2.0, lambda: all_markers("android/app/src/main/java/com/eabusham/routervpn/AndroidNodeStore.java", "MAX_NODES = 24", "stableNodeIdentity") and all_markers("android/app/src/main/java/com/eabusham/routervpn/AndroidMultihopController.java", '\"shadowsocks\".equals(exitMode)', '\"hysteria2\".equals(exitMode)', 'proxy.put(\"detour\", \"entry-wg\")')),''':
'''    Gate("Android real narrow multihop + multi-node store", 2.0, lambda: all_markers("android/app/src/main/java/com/eabusham/routervpn/AndroidNodeStore.java", "MAX_NODES = 24", "stableNodeIdentity") and all_markers("android/app/src/main/java/com/eabusham/routervpn/AndroidMultihopController.java", '\"shadowsocks\".equals(exitMode)', '\"hysteria2\".equals(exitMode)', 'proxy.put(\"detour\", \"entry-wg\")') and all_markers("android/app/src/main/java/com/eabusham/routervpn/AndroidMultihopRuntime.java", "AndroidPathProbe.prove(prepared.exitBundle", "Exit-node private path proof failed", "if (started) singBox.stop()")),''',
}

for old, new in replacements.items():
    if new in t:
        continue
    if t.count(old) != 1:
        raise SystemExit(f"weighted Android gate anchor mismatch: {old[:90]!r} count={t.count(old)}")
    t = t.replace(old, new, 1)

p.write_text(t, encoding="utf-8")
print("Migrated weighted Android source gates without changing the 88/12 weights")
