#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
full = ROOT / "deploy/full-audit-v4.py"
go = ROOT / "internal/common/native_runtime_contract_test.go"

ft = full.read_text(encoding="utf-8")
ft = ft.replace('"Strict embedded libbox sessions require"', '"Strict embedded libbox/Xray sessions require"')
anchor = 'need("android/app/src/main/java/com/eabusham/routervpn/NativeSingBoxController.java","isDirectFullDeviceConfig","MAX_PROFILE_FILE","MAX_PROFILE_TOTAL","cleanupOldSessions")\n'
insert = anchor + '''need("android/app/src/main/java/com/eabusham/routervpn/NativeXrayController.java","isCompositeProfile","cannot be represented truthfully by native Xray alone","AndroidNativeProfilePolicy.selectedPlainUdpDns(root)","AndroidNativeProfilePolicy.selectedMtu(root, 1380)")
need("android/app/src/main/java/com/eabusham/routervpn/XrayVpnService.java","registerDialerController","registerListenerController",'env.put("xray.tun.fd"',"AndroidPathProbe.prove(activeBundle","restartAfterNetworkChange","isLockdownEnabled()")
need("android/app/src/main/java/com/eabusham/routervpn/AndroidNativeProfilePolicy.java","patchWireGuardLikeConfig","selectedPlainUdpDns","requires an encrypted/transport-aware resolver","cannot be enforced by Android's address-only native VPN DNS API")
need("android/app/src/main/java/com/eabusham/routervpn/AndroidUnderlyingNetworkMonitor.java","NET_CAPABILITY_NOT_VPN","initialized && (current == null || !current.equals(network))")
'''
if "AndroidNativeProfilePolicy.java" not in ft:
    if ft.count(anchor) != 1:
        raise SystemExit(f"full-audit Android insertion anchor mismatch: {ft.count(anchor)}")
    ft = ft.replace(anchor, insert, 1)
old_orch = 'need("android/app/src/main/java/com/eabusham/routervpn/AndroidModeOrchestrator.java","AndroidPathProbe.prove(bundle","No candidate passed selected-node path proof","SMART AUTO could not restore its last-known-good mode")'
new_orch = 'need("android/app/src/main/java/com/eabusham/routervpn/AndroidModeOrchestrator.java","AndroidPathProbe.prove(bundle","No candidate passed selected-node path proof","SMART AUTO could not restore its last-known-good mode","void all(File bundle,Callback cb)","protectionRank","ALL failed closed because no Android-native branch passed selected-node path proof","Composite desktop MAX chains remain separate and are never faked on Android")'
if old_orch in ft:
    ft = ft.replace(old_orch, new_orch, 1)
elif new_orch not in ft:
    raise SystemExit("full-audit orchestrator anchor drifted")
old_wg = 'need("android/app/src/main/java/com/eabusham/routervpn/NativeWireGuardController.java","GoBackend","State.UP","Config.parse",\'optJSONObject("wg")\',"AndroidKillSwitchPolicy.strictRequested(privateBundle)")'
new_wg = 'need("android/app/src/main/java/com/eabusham/routervpn/NativeWireGuardController.java","GoBackend","State.UP","Config.parse",\'optJSONObject("wg")\',"AndroidKillSwitchPolicy.strictRequested(privateBundle)","AndroidNativeProfilePolicy.patchWireGuardLikeConfig","AndroidPathProbe.prove(privateBundle, 8000)","recoverAfterNetworkChange","network-transition recovery failed closed")'
if old_wg in ft: ft = ft.replace(old_wg,new_wg,1)
old_awg = 'need("android/app/src/main/java/com/eabusham/routervpn/NativeAmneziaWGController.java","org.amnezia.awg.backend.GoBackend","State.UP","Config.parse",\'optJSONObject("awg2-fast")\',"AndroidKillSwitchPolicy.strictRequested(privateBundle)")'
new_awg = 'need("android/app/src/main/java/com/eabusham/routervpn/NativeAmneziaWGController.java","org.amnezia.awg.backend.GoBackend","State.UP","Config.parse",\'optJSONObject("awg2-fast")\',"AndroidKillSwitchPolicy.strictRequested(privateBundle)","AndroidNativeProfilePolicy.patchWireGuardLikeConfig","AndroidPathProbe.prove(privateBundle, 8000)","recoverAfterNetworkChange","network-transition recovery failed closed")'
if old_awg in ft: ft = ft.replace(old_awg,new_awg,1)
full.write_text(ft,encoding="utf-8")

gt = go.read_text(encoding="utf-8")
gt = gt.replace('"Strict embedded libbox sessions require"', '"Strict embedded libbox/Xray sessions require"')
gt = gt.replace('"Network changes reset libbox"', '"Network changes reset/revalidate libbox and native Xray"')
old_orch_go = 'for _,required:=range []string{"AndroidPathProbe.prove(bundle","No candidate passed selected-node path proof","SMART AUTO could not restore its last-known-good mode"}'
new_orch_go = 'for _,required:=range []string{"AndroidPathProbe.prove(bundle","No candidate passed selected-node path proof","SMART AUTO could not restore its last-known-good mode","void all(File bundle,Callback cb)","protectionRank","ALL failed closed because no Android-native branch passed selected-node path proof"}'
if old_orch_go in gt: gt = gt.replace(old_orch_go,new_orch_go,1)
wg_marker = '"AndroidKillSwitchPolicy.strictRequested(privateBundle)"}'
wg_add = '"AndroidKillSwitchPolicy.strictRequested(privateBundle)","AndroidNativeProfilePolicy.patchWireGuardLikeConfig","AndroidPathProbe.prove(privateBundle, 8000)","recoverAfterNetworkChange","network-transition recovery failed closed"}'
# There are two controller lists; upgrade both exactly.
if gt.count(wg_marker) == 2:
    gt = gt.replace(wg_marker,wg_add,2)

sing_anchor = '\tsing:=repoFile(t,"android/app/src/main/java/com/eabusham/routervpn/NativeSingBoxController.java")\n\tfor _,required:=range []string{"isDirectFullDeviceConfig","MAX_PROFILE_FILE","MAX_PROFILE_TOTAL","cleanupOldSessions","LayeredVpnService"}{if !strings.Contains(sing,required){t.Fatalf("Android embedded libbox runtime missing %q",required)}}\n'
if 'xray:=repoFile(t,"android/app/src/main/java/com/eabusham/routervpn/NativeXrayController.java")' not in gt:
    if gt.count(sing_anchor) != 1:
        raise SystemExit(f"native Go Xray insertion anchor mismatch: {gt.count(sing_anchor)}")
    go_insert = sing_anchor + '''\txray:=repoFile(t,"android/app/src/main/java/com/eabusham/routervpn/NativeXrayController.java")
\tfor _,required:=range []string{"isCompositeProfile","cannot be represented truthfully by native Xray alone","AndroidNativeProfilePolicy.selectedPlainUdpDns(root)","AndroidNativeProfilePolicy.selectedMtu(root, 1380)"}{if !strings.Contains(xray,required){t.Fatalf("Android native Xray controller missing %q",required)}}
\txrayService:=repoFile(t,"android/app/src/main/java/com/eabusham/routervpn/XrayVpnService.java")
\tfor _,required:=range []string{"registerDialerController","registerListenerController",`env.put("xray.tun.fd"`,"AndroidPathProbe.prove(activeBundle","restartAfterNetworkChange","isLockdownEnabled()"}{if !strings.Contains(xrayService,required){t.Fatalf("Android native Xray VpnService missing %q",required)}}
\tnativePolicy:=repoFile(t,"android/app/src/main/java/com/eabusham/routervpn/AndroidNativeProfilePolicy.java")
\tfor _,required:=range []string{"patchWireGuardLikeConfig","selectedPlainUdpDns","requires an encrypted/transport-aware resolver","cannot be enforced by Android's address-only native VPN DNS API"}{if !strings.Contains(nativePolicy,required){t.Fatalf("Android native DNS/MTU policy missing %q",required)}}
'''
    gt = gt.replace(sing_anchor,go_insert,1)
go.write_text(gt,encoding="utf-8")
print("Migrated Android Xray/ALL/native-policy repository audits")
