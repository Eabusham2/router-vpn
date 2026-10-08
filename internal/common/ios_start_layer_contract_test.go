package common

import (
	"strings"
	"testing"
)

func TestAppleStartLayerIsComposedByOwnedAuthenticatedPacketTunnel(t *testing.T) {
	composer := repoFile(t, "ios/RouterVPN/PacketTunnel/IOSStartLayer.swift")
	for _, required := range []string{
		`static let aes = "aes-256-gcm"`,
		`static let aesXOR = "aes-256-gcm+xor-whitening"`,
		`static let aesMethod = "2022-blake3-aes-256-gcm"`,
		`private static let supportedRawModes: Set<String> = ["wg", "awg2-fast", "awg2-strong", "shadowsocks", "hysteria2", "naive-h2", "naive-h3"]`,
		"Start Layer requires authenticated Shadowsocks 2022 BLAKE3 AES-256-GCM",
		`static let nativeWhiteningType = "routervpn-aes-xor"`,
		"XOR is obfuscation only",
		"LibboxRouterComposeNativeBaseStartLayer(configText, sourceText, policy, &failure)",
		`"node_kind": kind, "router_api": routerAPI`,
		`data.base64EncodedString() == encoded`,
		`result["sing-box.json"] = Data(composed.utf8)`,
		`outbounds[proxyIndex]["server"] = "127.0.0.1"`,
		`outbounds[proxyIndex]["detour"] = aesTag`,
		`result["sing-box.json"] = composed`,
		"External nodes own their own transport security",
		"Start Layer will not overwrite it",
	} {
		if !strings.Contains(composer, required) {
			t.Fatalf("iOS Start Layer composition/fail-closed boundary missing %q", required)
		}
	}
	if strings.Contains(composer, "XORWhitening = true") || strings.Contains(composer, "xor_counts_as_encryption") {
		t.Fatal("iOS Start Layer must not score XOR whitening as encryption")
	}

	provider := repoFile(t, "ios/RouterVPN/PacketTunnel/PacketTunnelProvider.swift")
	for _, required := range []string{
		"try IOSStartLayer.validateWireGuard(profile: selectedProfile)",
		"rawFiles = try layeredProfile(root, rawProfileID: rawProfileID)",
		"let composedFiles = try IOSStartLayer.apply(root: root, selectedProfile: selectedProfile, files: rawFiles, rawProfileID: rawProfileID)",
		"var files = try RouterVPNMTUPolicy.libbox(composedFiles, profile: selectedProfile)",
		"try IOSStartLayer.validateExternal(profile: selectedProfile)",
		"try engine.start(files: files, strict: strict)",
		"proveSelectedNode(url: proofURL, expectedNodeID: expectedNodeID",
	} {
		if !strings.Contains(provider, required) {
			t.Fatalf("PacketTunnel does not enforce iOS Start Layer runtime truth: missing %q", required)
		}
	}

	// The engine must receive the result of both composers, in that order.
	start := strings.Index(provider, "private func startLibbox(")
	end := strings.Index(provider, "private func startExternalLibbox(")
	if start < 0 || end <= start {
		t.Fatal("PacketTunnel Libbox composition owner is missing")
	}
	body := provider[start:end]
	native := strings.Index(body, "LibboxRouterCompileXrayProfile(")
	compose := strings.Index(body, "let composedFiles = try IOSStartLayer.apply(")
	mtu := strings.Index(body, "var files = try RouterVPNMTUPolicy.libbox(composedFiles,")
	run := strings.Index(body, "try engine.start(files: files, strict: strict)")
	if native < 0 || compose <= native || mtu <= compose || run <= mtu {
		t.Fatal("Start Layer and MTU must both compose before the native engine starts")
	}

	for _, required := range []string{
		"RouterVPNMultihopGraph.wireGuardFiles(",
		"RouterVPNMultihopGraph.singleWireGuardPolicy(",
		"LibboxRouterApplyMultihopLANPolicy(",
		"let provenNodeID = expectedNodeID",
	} {
		position := strings.Index(body, required)
		if position < 0 || position >= run {
			t.Fatalf("native WG validation must precede engine launch: %q", required)
		}
	}

	selector := repoFile(t, "ios/RouterVPN/App/IOSRuntimeSelection.swift")
	for _, required := range []string{
		`private static let startLayerRawModes: Set<String> = ["wg", "awg2-fast", "awg2-strong", "shadowsocks", "hysteria2", "naive-h2", "naive-h3"]`,
		"try validateStartLayer(bundle: bundle, rawProfileID: rawProfileID)",
		"Start Layer AES-256-GCM requires an owned Libbox WG/AWG",
		"start == startLayerAES || start == startLayerAESXOR",
		"routervpn-aes-xor",
	} {
		if !strings.Contains(selector, required) {
			t.Fatalf("iOS runtime selector can choose an engine that cannot honor Start Layer: missing %q", required)
		}
	}

	settings := repoFile(t, "ios/RouterVPN/App/IOSProfileSettingsView.swift")
	for _, required := range []string{
		`@State private var startLayer = "off"`,
		"AES-256-GCM — authenticated Libbox modes",
		"AES-256-GCM + XOR whitening — native",
		"tunnel-owned native outbound",
		"XOR is obfuscation only and is never counted as encryption",
		`startLayer = (p.startLayer ?? "off").lowercased()`,
		"p.startLayer = startLayer",
	} {
		if !strings.Contains(settings, required) {
			t.Fatalf("iOS native Settings can no longer configure Start Layer truthfully: missing %q", required)
		}
	}

	profiles := repoFile(t, "ios/RouterVPN/App/IOSConnectionProfilesView.swift")
	for _, required := range []string{
		"var startLayer: String",
		`startLayer = try c.decodeIfPresent(String.self, forKey: .startLayer) ?? "off"`,
		`startLayer: (selected.startLayer ?? "off").lowercased()`,
		"profile.startLayer = prefs.startLayer",
		"iosConnectionProfilesSchemaVersion = 4",
	} {
		if !strings.Contains(profiles, required) {
			t.Fatalf("iOS whole connection profiles no longer preserve Start Layer: missing %q", required)
		}
	}

	project := repoFile(t, "ios/RouterVPN/project.yml")
	if !strings.Contains(project, "sources: [PacketTunnel]") {
		t.Fatal("PacketTunnel target no longer composes the PacketTunnel source directory containing IOSStartLayer.swift")
	}
}

// A mode list is not implementation proof. Keep both native host call paths
// connected to the shipping Go composer and retain raw-backend rejection.
func TestNativeBaseStartLayerHostsShareTheCompiler(t *testing.T) {
	sources := map[string][]string{
		"mobile/routervpn_multihop_bridge.go.tmpl": {
			"func RouterComposeNativeBaseStartLayer(",
			"return mobilemultihop.ComposeNativeBaseStartLayer(config, shadowsocks, policy)",
		},
		"ios/RouterVPN/App/IOSDNSRuntimePolicy.swift": {
			"let layeredBase =", "return layeredBase || adaptiveMTU",
		},
		"android/app/src/main/java/com/eabusham/routervpn/AndroidNativeProfilePolicy.java": {
			"if (!AndroidStartLayer.OFF.equals(AndroidStartLayer.selectedMode(bundle))) return true;",
		},
		"android/app/src/main/java/com/eabusham/routervpn/AndroidStartLayer.java": {
			"Libbox.routerComposeNativeBaseStartLayer(targetConfig.toString(), sourceText, policy.toString())",
			"AndroidProfileSelection.selectedRouterProfile(bundle)",
		},
		"android/app/src/main/java/com/eabusham/routervpn/NativeSingBoxController.java": {
			"AndroidStartLayer.apply(root, config, id)",
			"AndroidStartLayer.apply(root, patchedConfig, modeId)",
		},
		"ios/RouterVPN/test_runtime_selection_contract.py": {"deploy/test_ios_native_base_start_layer.py"},
		"mobile/routervpn_multihop_native_test.go.tmpl":    {"func TestRouterNativeBaseStartLayerGraph("},
	}
	for path, markers := range sources {
		source := repoFile(t, path)
		for _, marker := range markers {
			if !strings.Contains(source, marker) {
				t.Errorf("native Start Layer missing %s in %s", marker, path)
			}
		}
	}
	provider := repoFile(t, "ios/RouterVPN/PacketTunnel/PacketTunnelProvider.swift")
	start := strings.Index(provider, "private func startWireGuard(")
	end := strings.Index(provider, "private func startMultihop(")
	if start < 0 || end <= start || !strings.Contains(provider[start:end], "try IOSStartLayer.validateWireGuard(profile: selectedProfile)") {
		t.Fatal("raw WireGuardKit must not silently ignore a requested Start Layer")
	}
}
