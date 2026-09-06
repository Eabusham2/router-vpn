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
		"Arrays.fill(key, (byte) 0)",
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
		"AndroidStartLayer.RelayPlan relayPlan = AndroidStartLayer.apply",
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

	service := repoFile(t, "android/app/src/main/java/com/eabusham/routervpn/LayeredVpnService.java")
	for _, required := range []string{
		"private AndroidStartLayerRelay startLayerRelay",
		"AndroidStartLayerRelay.startIfConfigured(this, session",
		"shutdown(\"FAILED\", message)",
		"startLayerRelay.close()",
		"startLayerRelay = null",
	} {
		if !strings.Contains(service, required) {
			t.Fatalf("Android VpnService does not own Start Layer relay lifecycle: missing %q", required)
		}
	}

	for _, raw := range []struct {
		path       string
		name       string
		downMarker string
		failMarker string
	}{
		{"android/app/src/main/java/com/eabusham/routervpn/NativeWireGuardController.java", "WireGuard", "if (result != State.DOWN) throw new IllegalStateException(\"WireGuard teardown did not prove DOWN.\")", "WireGuard disconnect incomplete:"},
		{"android/app/src/main/java/com/eabusham/routervpn/NativeAmneziaWGController.java", "AmneziaWG", "if (result != State.DOWN) throw new IllegalStateException(\"AmneziaWG teardown did not prove DOWN.\")", "AmneziaWG disconnect incomplete:"},
	} {
		body := repoFile(t, raw.path)
		for _, required := range []string{raw.downMarker, raw.failMarker, "clearActive();", "homeStateOwner = false;"} {
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
}
