package common

import (
	"strings"
	"testing"
)

func TestAndroidNativeXrayUsesOneOwnedService(t *testing.T) {
	for path, markers := range map[string][]string{
		"android/app/src/main/java/com/eabusham/routervpn/AndroidXrayLibboxPolicy.java": {
			"Libbox.routerCheckXrayProfile", "Libbox.routerResolveXrayStartLayerProfile",
			"Libbox.routerCompileXrayProfile", "Libbox.routerApplyNativeXrayDevicePolicy",
			"normalizeDnsRoutes", "Thread.currentThread().isInterrupted()",
		},
		"android/app/src/main/java/com/eabusham/routervpn/NativeSingBoxController.java": {
			"AndroidXrayLibboxPolicy.resolve(root, profile, modeId)",
			"AndroidXrayLibboxPolicy.check(bundle, profile, modeId)",
			"AndroidXrayLibboxPolicy.applyDevice(root, patchedConfig)",
			"AndroidXrayLibboxPolicy.normalizeDnsRoutes(patchedConfig)",
			"capturedBundle.equals(loadBundle(privateBundle).toString())",
		},
		"android/app/src/main/java/com/eabusham/routervpn/AndroidModeOrchestrator.java": {
			"directXray.contains(id)&&!AndroidStartLayer.nativeXray(id)",
		},
		"android/app/src/main/java/com/eabusham/routervpn/NativeXrayController.java": {
			"!safeToken(id) || AndroidStartLayer.nativeXray(id)",
			"legacy startup cannot bypass native validation",
		},
		"android/app/src/main/java/com/eabusham/routervpn/AndroidStartLayer.java": {
			"Libbox.routerComposeXrayStartLayer", "nativeXray(mode)",
			"exactNativeAsset(profiles.getJSONObject(mode), \"xray.json\")",
		},
		"android/build-sing-box-libbox.sh": {
			"NATIVE_XRAY_SHA=", "$XRAY_POLICY_SHA+$NATIVE_XRAY_SHA",
			"prepare-apple-xray.py\" \"$VENDOR\" \"$XRAY_CORE_VENDOR\"", "test_apple_xray_pinned.sh",
			"routerResolveXrayStartLayerProfile", "routerApplyNativeXrayDevicePolicy",
		},
		"android/test_android_multihop_graph.py": {
			"nativeXrayChecks", "readiness performed network bootstrap",
			"source updated during hostname resolution", "unowned Xray helper staged source",
			"stale or cancelled native preparation staged a session",
		},
	} {
		source := repoFile(t, path)
		for _, marker := range markers {
			if !strings.Contains(source, marker) {
				t.Errorf("%s missing %s", path, marker)
			}
		}
	}
	preparation := repoFile(t, "android/app/src/main/java/com/eabusham/routervpn/AndroidXrayLibboxPolicy.java")
	for _, forbidden := range []string{"startService(", "startForegroundService(", "new NativeXrayController(", "routerXrayRegisterDialerController("} {
		if strings.Contains(preparation, forbidden) {
			t.Errorf("native preparation starts another service: %s", forbidden)
		}
	}
}
