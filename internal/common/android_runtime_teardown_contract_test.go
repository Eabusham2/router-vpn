package common

import (
	"strings"
	"testing"
)

func TestAndroidRuntimeTeardownRetainsOwnershipUntilTerminalState(t *testing.T) {
	for _, raw := range []struct {
		path       string
		name       string
		downMarker string
		failMarker string
	}{
		{"android/app/src/main/java/com/eabusham/routervpn/NativeWireGuardController.java", "WireGuard", "WireGuard teardown did not prove DOWN.", "WireGuard disconnect incomplete:"},
		{"android/app/src/main/java/com/eabusham/routervpn/NativeAmneziaWGController.java", "AmneziaWG", "AmneziaWG teardown did not prove DOWN.", "AmneziaWG disconnect incomplete:"},
	} {
		body := repoFile(t, raw.path)
		for _, marker := range []string{raw.downMarker, raw.failMarker, "clearActive();", "homeStateOwner = false;"} {
			if !strings.Contains(body, marker) {
				t.Fatalf("Android %s teardown ownership missing %q", raw.name, marker)
			}
		}
		proof := strings.Index(body, raw.downMarker)
		if proof < 0 || strings.Index(body[proof:], "clearActive();") < 0 || strings.Index(body[proof:], "homeStateOwner = false;") < 0 {
			t.Fatalf("Android %s can release runtime ownership before DOWN proof", raw.name)
		}
	}

	multihop := repoFile(t, "android/app/src/main/java/com/eabusham/routervpn/AndroidMultihopRuntime.java")
	for _, marker := range []string{
		"STOP_TIMEOUT_MS = 8000L",
		"stopEmbeddedAndProve()",
		"Android multihop teardown did not reach DOWN/FAILED/REVOKED before timeout.",
		"Android multihop disconnect did not prove embedded engine teardown; runtime ownership retained.",
		"return \"multihop\".equals(home.logicalMode) && runtimeBusy(singBox.getState());",
	} {
		if !strings.Contains(multihop, marker) {
			t.Fatalf("Android multihop teardown ownership missing %q", marker)
		}
	}
	if strings.Contains(multihop, "singBox.stop();\n        AndroidHomeStateStore.disconnected(context);") {
		t.Fatal("Android multihop still publishes disconnected immediately after an asynchronous stop request")
	}

	external := repoFile(t, "android/app/src/main/java/com/eabusham/routervpn/AndroidStandardExitRuntime.java")
	for _, marker := range []string{
		"STOP_TIMEOUT_MS=8000L",
		"stopEmbeddedAndProve()",
		"Android custom-exit teardown did not reach DOWN/FAILED/REVOKED before timeout.",
		"Android custom-exit disconnect did not prove embedded engine teardown; runtime ownership retained.",
		"Embedded engine teardown was not proved; runtime ownership retained.",
	} {
		if !strings.Contains(external, marker) {
			t.Fatalf("Android custom-exit teardown ownership missing %q", marker)
		}
	}
	if strings.Contains(external, "singBox.stop();AndroidHomeStateStore.disconnected(context);") {
		t.Fatal("Android custom exit still publishes disconnected immediately after an asynchronous stop request")
	}

	home := repoFile(t, "android/app/src/main/java/com/eabusham/routervpn/AndroidHomeSummary.java")
	for _, marker := range []string{
		"Raw WireGuard/AmneziaWG teardown timed out; session ownership retained.",
		"WireGuard did not prove DOWN during Emergency Disconnect.",
		"AmneziaWG did not prove DOWN during Emergency Disconnect.",
		"all raw tunnels proved DOWN and no Router VPN-owned VPN network remains",
	} {
		if !strings.Contains(home, marker) {
			t.Fatalf("Android Emergency Disconnect teardown proof missing %q", marker)
		}
	}
}
