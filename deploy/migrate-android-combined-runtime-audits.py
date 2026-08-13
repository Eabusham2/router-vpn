#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
full = ROOT / "deploy/full-audit-v4.py"
go = ROOT / "internal/common/native_runtime_contract_test.go"
weighted = ROOT / "deploy/weighted-release-audit.py"

ft = full.read_text(encoding="utf-8")
old = 'need("android/app/src/main/java/com/eabusham/routervpn/XrayVpnService.java","registerDialerController","registerListenerController",\'env.put("xray.tun.fd"\',"AndroidPathProbe.prove(activeBundle","restartAfterNetworkChange","isLockdownEnabled()")'
new = 'need("android/app/src/main/java/com/eabusham/routervpn/XrayVpnService.java","routerXrayRegisterDialerController","routerXrayRegisterListenerController","routerXraySetDNS","routerXrayResetDNS","routerXrayBridgeRevision",\'env.put("xray.tun.fd"\',"AndroidPathProbe.prove(activeBundle","restartAfterNetworkChange","isLockdownEnabled()")'
if old in ft:
    ft = ft.replace(old, new, 1)
elif new not in ft:
    raise SystemExit("full-audit Xray service marker drifted")
android_gradle = 'need("android/app/build.gradle","com.wireguard.android:tunnel:1.0.20260102")\n'
combined = android_gradle + '''need("android/app/build.gradle","libs/libbox.aar")
no("android/app/build.gradle","libs/libxray.aar","prepareXrayLibXray")
need("android/build-sing-box-libbox.sh","LIBXRAY_COMMIT=294fb37343205b9b0cb7b7b1b423d3d4b60d9998","XRAY_CORE_VERSION=v1.260327.1-0.20260711155151-50231eaff98c","GO_TOOLCHAIN=go1.26.3","exactly one gomobile go.Seq runtime class","github.com/xtls/libxray=$XRAY_VENDOR")
need("android/routervpn_xray_bridge.go","RouterXrayDialerController","RouterXrayRegisterDialerController","RouterXrayRegisterListenerController","RouterXraySetDNS","RouterXrayResetDNS","RouterXrayInvoke","net.DefaultResolver","controller.ProtectFd(int64(fd))")
'''
if 'android/routervpn_xray_bridge.go' not in ft:
    if ft.count(android_gradle) != 1:
        raise SystemExit(f"full-audit combined runtime insertion anchor mismatch: {ft.count(android_gradle)}")
    ft = ft.replace(android_gradle, combined, 1)
else:
    ft = ft.replace('need("android/app/build.gradle","libs/libbox.aar","one pinned gomobile runtime")', 'need("android/app/build.gradle","libs/libbox.aar")')
full.write_text(ft, encoding="utf-8")

gt = go.read_text(encoding="utf-8")
old_list = '[]string{"registerDialerController", "registerListenerController", `env.put("xray.tun.fd"`, "AndroidPathProbe.prove(activeBundle", "restartAfterNetworkChange", "isLockdownEnabled()"}'
new_list = '[]string{"routerXrayRegisterDialerController", "routerXrayRegisterListenerController", "routerXraySetDNS", "routerXrayResetDNS", "routerXrayBridgeRevision", `env.put("xray.tun.fd"`, "AndroidPathProbe.prove(activeBundle", "restartAfterNetworkChange", "isLockdownEnabled()"}'
if old_list in gt:
    gt = gt.replace(old_list, new_list, 1)
elif new_list not in gt:
    raise SystemExit("Go native contract Xray service marker drifted")
insert_after = '''\tnativePolicy := repoFile(t, "android/app/src/main/java/com/eabusham/routervpn/AndroidNativeProfilePolicy.java")
\tfor _, required := range []string{"patchWireGuardLikeConfig", "selectedPlainUdpDns", "requires an encrypted/transport-aware resolver", "cannot be enforced by Android's address-only native VPN DNS API"} {
\t\tif !strings.Contains(nativePolicy, required) {
\t\t\tt.Fatalf("Android native DNS/MTU policy missing %q", required)
\t\t}
\t}
'''
if 'combinedBuild := repoFile(t, "android/build-sing-box-libbox.sh")' not in gt:
    if gt.count(insert_after) != 1:
        raise SystemExit(f"Go combined runtime insertion anchor mismatch: {gt.count(insert_after)}")
    addition = insert_after + '''\tcombinedBuild := repoFile(t, "android/build-sing-box-libbox.sh")
\tfor _, required := range []string{"LIBXRAY_COMMIT=294fb37343205b9b0cb7b7b1b423d3d4b60d9998", "XRAY_CORE_VERSION=v1.260327.1-0.20260711155151-50231eaff98c", "GO_TOOLCHAIN=go1.26.3", "exactly one gomobile go.Seq runtime class", "github.com/xtls/libxray=$XRAY_VENDOR"} {
\t\tif !strings.Contains(combinedBuild, required) { t.Fatalf("Android combined Go runtime build missing %q", required) }
\t}
\tbridge := repoFile(t, "android/routervpn_xray_bridge.go")
\tfor _, required := range []string{"RouterXrayDialerController", "RouterXrayRegisterDialerController", "RouterXrayRegisterListenerController", "RouterXraySetDNS", "RouterXrayResetDNS", "RouterXrayInvoke", "net.DefaultResolver", "controller.ProtectFd(int64(fd))"} {
\t\tif !strings.Contains(bridge, required) { t.Fatalf("Android combined Xray bridge missing %q", required) }
\t}
\tcombinedGradle := repoFile(t, "android/app/build.gradle")
\tif !strings.Contains(combinedGradle, "libs/libbox.aar") || strings.Contains(combinedGradle, "libs/libxray.aar") || strings.Contains(combinedGradle, "prepareXrayLibXray") {
\t\tt.Fatal("Android Gradle must package one combined libbox Go runtime and no standalone libXray AAR")
\t}
'''
    gt = gt.replace(insert_after, addition, 1)
go.write_text(gt, encoding="utf-8")

wt = weighted.read_text(encoding="utf-8")
old_strict = 'all_markers("android/app/src/main/java/com/eabusham/routervpn/XrayVpnService.java", "isAlwaysOn()", "isLockdownEnabled()", "registerDialerController", "restartAfterNetworkChange", "AndroidPathProbe.prove(activeBundle")'
new_strict = 'all_markers("android/app/src/main/java/com/eabusham/routervpn/XrayVpnService.java", "isAlwaysOn()", "isLockdownEnabled()", "routerXrayRegisterDialerController", "routerXraySetDNS", "routerXrayResetDNS", "restartAfterNetworkChange", "AndroidPathProbe.prove(activeBundle")'
if old_strict in wt:
    wt = wt.replace(old_strict, new_strict, 1)
elif new_strict not in wt:
    raise SystemExit("weighted Xray strict gate marker drifted")
old_embedded_tail = 'and exists("android/app/src/main/java/com/eabusham/routervpn/LayeredVpnService.java") and exists("android/app/src/main/java/com/eabusham/routervpn/XrayVpnService.java")),'
new_embedded_tail = 'and exists("android/app/src/main/java/com/eabusham/routervpn/LayeredVpnService.java") and exists("android/app/src/main/java/com/eabusham/routervpn/XrayVpnService.java") and all_markers("android/build-sing-box-libbox.sh", "LIBXRAY_COMMIT=294fb37343205b9b0cb7b7b1b423d3d4b60d9998", "exactly one gomobile go.Seq runtime class") and none_markers("android/app/build.gradle", "libs/libxray.aar", "prepareXrayLibXray")),'
if new_embedded_tail not in wt:
    if wt.count(old_embedded_tail) != 1:
        raise SystemExit(f"weighted embedded combined-runtime anchor mismatch: {wt.count(old_embedded_tail)}")
    wt = wt.replace(old_embedded_tail, new_embedded_tail, 1)
weighted.write_text(wt, encoding="utf-8")
print("Migrated global audits to the one-AAR Android Go runtime")
