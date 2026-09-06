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
		"boolean revalidationTeardown",
		"boolean stopped = stopEmbeddedAndProve();",
		"suppressHome = revalidationTeardown",
		"Android multihop teardown did not reach DOWN/FAILED/REVOKED before timeout.",
		"Android multihop disconnect did not prove embedded engine teardown; runtime ownership retained.",
		"return \"multihop\".equals(home.logicalMode) && runtimeBusy(singBox.getState());",
	} {
		if !strings.Contains(multihop, marker) {
			t.Fatalf("Android multihop teardown ownership missing %q", marker)
		}
	}
	for _, forbidden := range []string{
		"synchronized void disconnect()",
		"synchronized void failClosedForRevalidation()",
		"singBox.stop();\n        AndroidHomeStateStore.disconnected(context);",
	} {
		if strings.Contains(multihop, forbidden) {
			t.Fatalf("Android multihop teardown still blocks its monitor or publishes stale Home state: %q", forbidden)
		}
	}

	external := repoFile(t, "android/app/src/main/java/com/eabusham/routervpn/AndroidStandardExitRuntime.java")
	for _, marker := range []string{
		"STOP_TIMEOUT_MS=8000L",
		"boolean disconnectRequested",
		"boolean revalidationTeardown",
		"boolean teardownInProgress",
		"Custom exit cancelled before Connected adoption.",
		"boolean stopped=stopEmbeddedAndProve();",
		"suppressHome=revalidationTeardown",
		"Android custom-exit teardown did not reach DOWN/FAILED/REVOKED before timeout.",
		"Android custom-exit disconnect did not prove embedded engine teardown; runtime ownership retained.",
		"Embedded engine teardown was not proved; runtime ownership retained.",
	} {
		if !strings.Contains(external, marker) {
			t.Fatalf("Android custom-exit teardown ownership missing %q", marker)
		}
	}
	for _, forbidden := range []string{
		"synchronized void disconnect()",
		"synchronized void failClosedForRevalidation()",
		"singBox.stop();AndroidHomeStateStore.disconnected(context);",
	} {
		if strings.Contains(external, forbidden) {
			t.Fatalf("Android custom-exit teardown still blocks its monitor or publishes stale Home state: %q", forbidden)
		}
	}

	unified := repoFile(t, "android/app/src/main/java/com/eabusham/routervpn/AndroidUnifiedConnectionController.java")
	for _, marker := range []string{
		"new AtomicBoolean(false)",
		"routervpn-unified-disconnect",
		"if(wasMultihop)multihop.disconnect();",
		"if(wasExternal)runtime.standardExit.disconnect();",
		"Disconnect incomplete:",
	} {
		if !strings.Contains(unified, marker) {
			t.Fatalf("Android unified disconnect nonblocking ownership proof missing %q", marker)
		}
	}

	home := repoFile(t, "android/app/src/main/java/com/eabusham/routervpn/AndroidHomeSummary.java")
	for _, marker := range []string{
		"routervpn-emergency-verify",
		"runtime.wireGuard.disconnectManaged",
		"runtime.amneziaWG.disconnectManaged",
		"try{runtime.multihop.failClosedForRevalidation();}catch(Throwable ignored){}",
		"try{runtime.standardExit.failClosedForRevalidation();}catch(Throwable ignored){}",
		"Raw WireGuard/AmneziaWG teardown timed out; session ownership retained.",
		"WireGuard did not prove DOWN during Emergency Disconnect.",
		"AmneziaWG did not prove DOWN during Emergency Disconnect.",
		"Libbox did not reach DOWN/FAILED/REVOKED during Emergency Disconnect.",
		"Xray did not reach DOWN/FAILED/REVOKED during Emergency Disconnect.",
		"all Router VPN engines proved terminal and no Router VPN-owned VPN network remains",
	} {
		if !strings.Contains(home, marker) {
			t.Fatalf("Android Emergency Disconnect teardown proof missing %q", marker)
		}
	}
	beforeThread := strings.Split(home, "new Thread(() -> {")[0]
	if strings.Contains(beforeThread, "runtime.multihop.disconnect()") || strings.Contains(beforeThread, "runtime.standardExit.disconnect()") {
		t.Fatal("Android Emergency Disconnect performs blocking runtime teardown on the caller/UI thread")
	}
}
