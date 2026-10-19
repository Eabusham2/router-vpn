package common

import (
	"strings"
	"testing"
)

func TestAndroidAESXORStartLayerOwnsProtectedRelayLifecycle(t *testing.T) {
	composer := repoFile(t, "android/app/src/main/java/com/eabusham/routervpn/AndroidStartLayer.java")
	for _, required := range []string{
		`AES_XOR = "aes-256-gcm+xor-whitening"`,
		`AES_METHOD = "2022-blake3-aes-256-gcm"`,
		`WHITENING_LABEL = "router-vpn-xor-whitening-v1\u0000"`,
		"MessageDigest.getInstance(\"SHA-256\")",
		"AndroidStartLayerRelay.LISTEN_PORT",
		"AndroidStartLayerRelay.SERVER_PORT",
		`ss.put("server", "127.0.0.1")`,
		`aes.put("server", "127.0.0.1")`,
		`inner.put("detour", AES_TAG)`,
		"XOR whitening is obfuscation only and requires authenticated AES-256-GCM",
	} {
		if !strings.Contains(composer, required) {
			t.Fatalf("Android Start Layer composer missing real AES+XOR boundary %q", required)
		}
	}

	relay := repoFile(t, "android/app/src/main/java/com/eabusham/routervpn/AndroidStartLayerRelay.java")
	for _, required := range []string{
		"extends", // class is intentionally standalone; protect calls below are the security boundary
		"service.protect(upstream)",
		"new ServerSocket()",
		"new DatagramSocket",
		"LISTEN_PORT = 18389",
		"SERVER_PORT = 8389",
		"target_port",
		"key_b64",
		"offset + i",
		"payload[i] ^ key[i % key.length]",
		"Arrays.fill(key,(byte)0)",
		"workers.awaitTermination(remaining,TimeUnit.NANOSECONDS)",
		"Start Layer teardown has not completed; its owner remains retained.",
		"start-layer-relay.json",
	} {
		if required == "extends" {
			continue
		}
		if !strings.Contains(relay, required) {
			t.Fatalf("Android protected Start Layer relay missing %q", required)
		}
	}
	if strings.Contains(relay, "XORCountsAsEncryption") || strings.Contains(relay, "encryption = xor") {
		t.Fatal("Android whitening relay must never claim XOR is encryption")
	}

	controller := repoFile(t, "android/app/src/main/java/com/eabusham/routervpn/NativeSingBoxController.java")
	for _, required := range []string{
		"AndroidStartLayer.RelayPlan relayPlan = AndroidNativeMAXProfile.isMode(modeId) ? null",
		"AndroidStartLayer.apply(root, patchedConfig, modeId)",
		"AndroidStartLayerRelay.SESSION_FILE",
		"relayPlan.metadata()",
		"relayPlan.clear()",
		"writeFile(new File(session, AndroidStartLayerRelay.SESSION_FILE), metadata)",
	} {
		if !strings.Contains(controller, required) {
			t.Fatalf("Android private Start Layer relay session wiring missing %q", required)
		}
	}

	orchestrator := repoFile(t, "android/app/src/main/java/com/eabusham/routervpn/AndroidModeOrchestrator.java")
	for _, required := range []string{
		"AndroidStartLayer.nativeCapabilityReason(currentBundle,c.id)",
		"if(kind!=Kind.LIBBOX||!AndroidStartLayer.supportsRawMode(id))continue;",
		"startAndProve(bundle,c,cb)",
		"failClosedAfterError(error)",
		"runtime cleanup failed: ",
		"WireGuard teardown did not prove DOWN before timeout.",
		"AmneziaWG teardown did not prove DOWN before timeout.",
		"Libbox teardown did not reach DOWN/FAILED/REVOKED before timeout.",
		"Xray teardown did not reach DOWN/FAILED/REVOKED before timeout.",
	} {
		if !strings.Contains(orchestrator, required) {
			t.Fatalf("Android AUTO/SMART/ALL runtime ownership contract missing %q", required)
		}
	}
	if strings.Contains(orchestrator, "if(AndroidStartLayer.AES_XOR.equals(startLayer))continue;") {
		t.Fatal("Android AUTO/SMART/ALL still filters AES+XOR even though the VpnService-owned protected relay is implemented")
	}
	if strings.Contains(orchestrator, "l.await(8,TimeUnit.SECONDS);}") {
		t.Fatal("Android orchestrator still releases ownership after an unverified asynchronous teardown wait")
	}
	if strings.Contains(orchestrator, "try{stopCurrent(false);}catch(Throwable ignored){}") {
		t.Fatal("Android orchestrator still swallows runtime cleanup failures")
	}

	service := repoFile(t, "android/app/src/main/java/com/eabusham/routervpn/LayeredVpnService.java")
	for _, required := range []string{
		"private AndroidStartLayerRelay startLayerRelay",
		"startLayerRelay = AndroidStartLayerRelay.prepareIfConfigured(this, session",
		"if(startLayerRelay!=null)startLayerRelay.start();",
		"shutdown(\"FAILED\", message)",
		"startLayerRelay.close()",
		"startLayerRelay = null",
	} {
		if !strings.Contains(service, required) {
			t.Fatalf("Android VpnService does not own Start Layer relay lifecycle: missing %q", required)
		}
	}
	prepare := strings.Index(service, "startLayerRelay = AndroidStartLayerRelay.prepareIfConfigured(this, session")
	activate := strings.Index(service, "if(startLayerRelay!=null)startLayerRelay.start();")
	engine := strings.Index(service, "commandServer = new CommandServer(this, this);")
	if prepare < 0 || activate <= prepare || engine <= activate {
		t.Fatal("Android must retain the prepared relay before starting its workers and then the native VPN engine")
	}

	for _, raw := range []struct {
		path             string
		name             string
		downMarker       string
		transitionMarker string
		failMarker       string
	}{
		{"android/app/src/main/java/com/eabusham/routervpn/NativeWireGuardController.java", "WireGuard", "if (result != State.DOWN) throw new IllegalStateException(\"WireGuard teardown did not prove DOWN.\")", "WireGuard network-transition teardown did not prove DOWN.", "WireGuard disconnect incomplete:"},
		{"android/app/src/main/java/com/eabusham/routervpn/NativeAmneziaWGController.java", "AmneziaWG", "if (result != State.DOWN) throw new IllegalStateException(\"AmneziaWG teardown did not prove DOWN.\")", "AmneziaWG network-transition teardown did not prove DOWN.", "AmneziaWG disconnect incomplete:"},
	} {
		body := repoFile(t, raw.path)
		for _, required := range []string{
			raw.downMarker,
			raw.transitionMarker,
			raw.failMarker,
			"clearActive();",
			"homeStateOwner = false;",
			"boolean emergency = publishHomeState && AndroidHomeStateStore.emergencyDisconnectPending(appContext);",
			"if (publishHomeState && !emergency)",
			"AndroidHomeStateStore.beginPathRevalidation(appContext,",
			"runtime ownership retained:",
			"Teardown incomplete; runtime ownership retained:",
			"callback.done(state,",
			"Emergency Disconnect requested; " + raw.name + " disconnect incomplete:",
		} {
			if !strings.Contains(body, required) {
				t.Fatalf("Android %s raw teardown ownership contract missing %q", raw.name, required)
			}
		}
		down := strings.Index(body, raw.downMarker)
		clear := strings.Index(body[down:], "clearActive();")
		release := strings.Index(body[down:], "homeStateOwner = false;")
		if down < 0 || clear < 0 || release < 0 {
			t.Fatalf("Android %s raw teardown ownership ordering could not be proved", raw.name)
		}
	}

	homeState := repoFile(t, "android/app/src/main/java/com/eabusham/routervpn/AndroidHomeStateStore.java")
	for _, required := range []string{
		`EMERGENCY_PREFIX = "Emergency Disconnect requested;"`,
		"static boolean emergencyDisconnectPending(Context context)",
		"runtime.wireGuard.getState() != com.wireguard.android.backend.Tunnel.State.DOWN",
		"runtime.amneziaWG.getState() != org.amnezia.awg.backend.Tunnel.State.DOWN",
		"Emergency Disconnect cannot release session ownership until WireGuard and AmneziaWG both prove DOWN.",
	} {
		if !strings.Contains(homeState, required) {
			t.Fatalf("Android emergency shared-session guard missing %q", required)
		}
	}

	home := repoFile(t, "android/app/src/main/java/com/eabusham/routervpn/AndroidHomeSummary.java")
	for _, required := range []string{
		"Emergency Disconnect requested; verifying every Router VPN transport stops.",
		"runtime.wireGuard.disconnect",
		"runtime.amneziaWG.disconnect",
		"AndroidHomeStateStore.disconnected(activity)",
		"Emergency Disconnect incomplete:",
	} {
		if !strings.Contains(home, required) {
			t.Fatalf("Android Emergency Disconnect transaction missing %q", required)
		}
	}
}

func androidMAXDispatchIsOwned(controller, compiler string) bool {
	compact := func(s string) string { return strings.Join(strings.Fields(s), " ") }
	controller, compiler = compact(controller), compact(compiler)
	start := strings.Index(controller, "SessionInfo prepareSession(")
	end := strings.Index(controller, "static JSONObject applyPerformance(")
	if start < 0 || end <= start {
		return false
	}
	body := controller[start:end]
	previous := -1
	for _, marker := range []string{
		"compileStandaloneProfile(root, profile, modeId)",
		"AndroidWireGuardLibboxPolicy.applyCompleteMAX(root, patchedConfig, modeId)",
		"AndroidStartLayer.RelayPlan relayPlan = AndroidNativeMAXProfile.isMode(modeId) ? null : AndroidStartLayer.apply(root, patchedConfig, modeId)",
		"if (nativePQFamily(modeId) || AndroidNativeMAXProfile.isMode(modeId)) RouterPQNative.install();",
		"Libbox.checkConfig(patchedConfig.toString());",
		"!capturedBundle.equals(loadBundle(privateBundle).toString())",
		"if (!session.mkdir())",
	} {
		index := strings.Index(body, marker)
		if index <= previous {
			return false
		}
		previous = index
	}
	for _, marker := range []string{
		"if (AndroidNativeMAXProfile.isMode(modeId)) return AndroidNativeMAXProfile.compile(bundle, profile, modeId);",
		"profile = new JSONObject().put(\"sing-box.json\", \"native-wireguard-graph\");",
	} {
		if !strings.Contains(controller, marker) {
			return false
		}
	}
	for _, marker := range []string{
		"validateAssets(assets, mode);",
		".put(\"start_layer\", layer)",
		"Libbox.routerCompileMAXProfile(mode, input, metadata.toString())",
		"validateGraph(bundle, assets, new JSONObject(compiled), mode);",
		"Arrays.fill(raw, (byte) 0)",
	} {
		if !strings.Contains(compiler, marker) {
			return false
		}
	}
	return true
}

func TestAndroidMAXDispatchRetainsOwnedCompilationAndFailureBoundaries(t *testing.T) {
	controller := repoFile(t, "android/app/src/main/java/com/eabusham/routervpn/NativeSingBoxController.java")
	compiler := repoFile(t, "android/app/src/main/java/com/eabusham/routervpn/AndroidNativeMAXProfile.java")
	if !androidMAXDispatchIsOwned(controller, compiler) {
		t.Fatal("complete MAX dispatch lost captured policy, runtime initialization or staging order")
	}
	for _, mutation := range [][2]string{
		{"AndroidNativeMAXProfile.isMode(modeId) ? null", "true ? null"},
		{"AndroidStartLayer.apply(root, patchedConfig, modeId)", "null"},
		{"return AndroidNativeMAXProfile.compile(bundle, profile, modeId);", "return ignored(bundle);"},
		{"AndroidWireGuardLibboxPolicy.applyCompleteMAX(root, patchedConfig, modeId)", "patchedConfig"},
		{"RouterPQNative.install();", "ignoredFactory();"},
		{"Libbox.checkConfig(patchedConfig.toString());", "acceptWithoutNativeValidation();"},
		{"!capturedBundle.equals(loadBundle(privateBundle).toString())", "false"},
	} {
		if !strings.Contains(controller, mutation[0]) {
			t.Fatal("negative control anchor missing", mutation[0])
		}
		if androidMAXDispatchIsOwned(strings.Replace(controller, mutation[0], mutation[1], 1), compiler) {
			t.Fatal("unowned dispatch accepted", mutation[0])
		}
	}
	for _, marker := range []string{"validateAssets(assets, mode);", ".put(\"start_layer\", layer)", "Libbox.routerCompileMAXProfile(mode, input, metadata.toString())", "validateGraph(bundle, assets, new JSONObject(compiled), mode);"} {
		if !strings.Contains(compiler, marker) {
			t.Fatal("negative compiler anchor missing", marker)
		}
		if androidMAXDispatchIsOwned(controller, strings.Replace(compiler, marker, "missing", 1)) {
			t.Fatal("unvalidated MAX compiler accepted", marker)
		}
	}
	release := repoFile(t, ".github/workflows/release-candidate.yml")
	if strings.Count(release, "python3 android/test_android_max_selection.py") != 2 {
		t.Fatal("both source and Android package gates must execute MAX host tests")
	}
}
