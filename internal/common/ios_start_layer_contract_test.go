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
		`private static let supportedRawModes: Set<String> = ["wg", "awg2-fast", "awg2-strong", "wg-pq", "awg2-pq", "shadowsocks", "ss-v2ray", "hysteria2", "naive-h2", "naive-h3", "reality-vision", "reality-pq-vision", "reality-xhttp", "split", "max"]`,
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
		"let completeChain = IOSNativeMAXProfile.modeIDs.contains(rawProfileID) || IOSNativeCompositeMultihop.modeIDs.contains(rawProfileID)",
		"let composedFiles = try completeChain ? rawFiles",
		": IOSStartLayer.apply(root: compositionRoot, selectedProfile: selectedProfile, files: rawFiles, rawProfileID: rawProfileID)",
		"var compositionRoot = root",
		"var files = try RouterVPNMTUPolicy.libbox(composedFiles, profile: selectedProfile)",
		"try IOSStartLayer.validateExternal(profile: selectedProfile)",
		"try engine.start(files: files, strict: strict)",
		"proveSelectedNode(url: proofURL, expectedNodeID: expectedNodeID",
	} {
		if !strings.Contains(provider, required) {
			t.Fatalf("PacketTunnel does not enforce iOS Start Layer runtime truth: missing %q", required)
		}
	}

	// Both callers receive only the completed compiler result. Keep the actual
	// compiler stages and the runtime's consumption/proof order separate.
	start := strings.Index(provider, "private func startLibbox(")
	end := strings.Index(provider, "private func startExternalLibbox(")
	if start < 0 || end <= start {
		t.Fatal("PacketTunnel Libbox composition owner is missing")
	}
	body := provider[start:end]
	compilerStart := strings.Index(body, "private func compileLibbox(")
	compilerEnd := strings.Index(body, "private func performanceFiles(")
	if compilerStart < 0 || compilerEnd <= compilerStart {
		t.Fatal("shared PacketTunnel compiler owner is missing")
	}
	compiler := body[compilerStart:compilerEnd]
	native := strings.Index(compiler, "LibboxRouterCompileXrayProfile(")
	compose := strings.Index(compiler, "let composedFiles = try completeChain ? rawFiles")
	mtu := strings.Index(compiler, "var files = try RouterVPNMTUPolicy.libbox(composedFiles,")
	result := strings.Index(compiler, "return LibboxCompilation(files: files, nodeID: expectedNodeID")
	if !appleSingleLayerDispatchIsOwned(body) || native < 0 || compose <= native || mtu <= compose || result <= mtu {
		t.Fatal("Start Layer and MTU must both compose before the native engine starts")
	}

	for _, required := range []string{
		"RouterVPNMultihopGraph.wireGuardFiles(",
		"RouterVPNMultihopGraph.singleWireGuardPolicy(",
		"LibboxRouterApplyMultihopLANPolicy(",
		"guard expectedNodeID.range(of:",
	} {
		position := strings.Index(compiler, required)
		if position < 0 || position >= result {
			t.Fatalf("native WG validation must precede engine launch: %q", required)
		}
	}

	selector := repoFile(t, "ios/RouterVPN/App/IOSRuntimeSelection.swift")
	for _, required := range []string{
		`private static let startLayerRawModes: Set<String> = ["wg", "awg2-fast", "awg2-strong", "wg-pq", "awg2-pq", "shadowsocks", "ss-v2ray", "hysteria2", "naive-h2", "naive-h3", "reality-vision", "reality-pq-vision", "reality-xhttp", "split", "max", "max-tls-wg", "max-tls-awg", "max-quic-wg", "max-quic-awg"]`,
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
		"Compatible native WG/AWG, PQ, proxy, Xray and complete MAX paths preserve the selected Start Layer",
		"including entry and exit layers in multihop",
		"AES+XOR uses an owned native outbound in the same VPN interface",
		"XOR adds obfuscation and always accompanies authenticated AES",
		`startLayer = (p.startLayer ?? "off").lowercased()`,
		"p.startLayer = startLayer",
	} {
		if !strings.Contains(settings, required) {
			t.Fatalf("iOS native Settings can no longer configure Start Layer truthfully: missing %q", required)
		}
	}
	for _, rejected := range []string{"Start Layer is unavailable for WG/AWG", "XOR is encryption", "XOR alone"} {
		if strings.Contains(settings, rejected) {
			t.Fatalf("iOS native Settings misrepresents the authenticated Start Layer: %q", rejected)
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

	requireApplePacketTunnelSources(t, "PacketTunnel", "App/IOSMultihopStartLayer.swift", "App/IOSNativePQProfile.swift", "App/IOSMultihopExecution.swift")
}

// Check exact source membership within the extension target. Other shared
// owners may join the target without removing its captured Start Layer policy.
func requireApplePacketTunnelSources(t *testing.T, required ...string) {
	t.Helper()
	project := repoFile(t, "ios/RouterVPN/project.yml")
	_, target, ok := strings.Cut(project, "\n  RouterVPNPacketTunnel:\n")
	if !ok {
		t.Fatal("PacketTunnel build target is missing")
	}
	sources := make(map[string]bool)
	for _, line := range strings.Split(target, "\n") {
		if strings.HasPrefix(line, "  ") && !strings.HasPrefix(line, "    ") {
			break
		}
		if !strings.HasPrefix(line, "    sources: [") || !strings.HasSuffix(line, "]") {
			continue
		}
		list := strings.TrimSuffix(strings.TrimPrefix(line, "    sources: ["), "]")
		for _, source := range strings.Split(list, ",") {
			sources[strings.TrimSpace(source)] = true
		}
	}
	for _, source := range required {
		if !sources[source] {
			t.Errorf("PacketTunnel target does not compile required source %q", source)
		}
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

// This is a source wiring contract, not a substitute for the executable Swift/Go
// MAX/composite tests. Complete-chain compilers consume their already-composed
// Start Layer. Every ordinary mode must still pass through IOSStartLayer.apply.
func appleSingleLayerDispatchIsOwned(body string) bool {
	normalized := strings.Join(strings.Fields(body), " ")
	compilerStart := strings.Index(normalized, "private func compileLibbox(")
	compilerEnd := strings.Index(normalized, "private func performanceFiles(")
	if compilerStart < 0 || compilerEnd <= compilerStart {
		return false
	}
	launch, compiler := normalized[:compilerStart], normalized[compilerStart:compilerEnd]
	family := strings.Index(compiler, "let completeChain = IOSNativeMAXProfile.modeIDs.contains(rawProfileID) || IOSNativeCompositeMultihop.modeIDs.contains(rawProfileID)")
	dispatch := "let composedFiles = try completeChain ? rawFiles : IOSStartLayer.apply(root: compositionRoot, selectedProfile: selectedProfile, files: rawFiles, rawProfileID: rawProfileID)"
	pos := strings.Index(compiler, dispatch)
	if pos < 0 || strings.Count(compiler, "let composedFiles =") != 1 || !strings.Contains(compiler, "var compositionRoot = root") {
		return false
	}
	compile := strings.Index(compiler, "rawFiles = try IOSNativeMAXProfile.compile(")
	selected := strings.Index(compiler, "let start = try IOSStartLayer.selectedMode(profile: selectedProfile)")
	capture := strings.Index(compiler, "profile: selectedProfile, startLayer: start)")
	bridge := strings.Index(compiler, "LibboxRouterCompileMAXProfile(mode, assets, metadata, &failure)")
	composite := strings.Index(compiler, "IOSNativeCompositeMultihop.capture(root: root, mode: rawProfileID,")
	compositeBridge := strings.Index(compiler, "LibboxRouterCompileCompositeProfile(mode, assets, policy, start, &failure)")
	baseProof := strings.Index(compiler, "LibboxRouterCompositeMultihopBase(source, mode, node, start, &failure)")
	complete := strings.Index(compiler, "Data(captured.source.utf8)")
	adopt := strings.Index(compiler, "rawFiles = [\"sing-box.json\": try JSONSerialization.data(withJSONObject: complete, options: [.sortedKeys])]")
	mtu := strings.Index(compiler, "var files = try RouterVPNMTUPolicy.libbox(composedFiles, profile: selectedProfile)")
	result := strings.Index(compiler, "return LibboxCompilation(files: files, nodeID: expectedNodeID,")
	prepare := strings.Index(launch, "let compiled = try compileLibbox(provider: provider, root: root, selectedProfile: selectedProfile)")
	consume := strings.Index(launch, "let files = compiled.files, provenNodeID = compiled.nodeID")
	run := strings.Index(launch, "try engine.start(files: files, strict: strict)")
	proof := strings.Index(launch, "proveSelectedNode(url: proofURL, expectedNodeID: provenNodeID")
	return selected >= 0 && compile > selected && capture > compile && bridge > capture &&
		composite > bridge && compositeBridge > composite && baseProof > compositeBridge && complete > baseProof && adopt > complete &&
		family > adopt && pos > family && mtu > pos && result > mtu &&
		prepare >= 0 && consume > prepare && run > consume && proof > run
}

func TestAppleSingleLayerDispatchRejectsUnownedMAXBypass(t *testing.T) {
	provider := repoFile(t, "ios/RouterVPN/PacketTunnel/PacketTunnelProvider.swift")
	start := strings.Index(provider, "private func startLibbox(")
	end := strings.Index(provider, "private func startExternalLibbox(")
	if start < 0 || end <= start {
		t.Fatal("missing native startup owner")
	}
	body := strings.ReplaceAll(provider[start:end], "\r\n", "\n")
	if !appleSingleLayerDispatchIsOwned(body) {
		t.Fatal("shipping MAX/ordinary dispatch is disconnected")
	}
	cases := [][2]string{
		{"let completeChain = IOSNativeMAXProfile.modeIDs.contains(rawProfileID) || IOSNativeCompositeMultihop.modeIDs.contains(rawProfileID)", "let completeChain = true"},
		{"try completeChain ? rawFiles", "try true ? rawFiles"},
		{"? rawFiles\n            : IOSStartLayer.apply(", "? rawFiles\n            : bypass("},
		{"rawFiles = try IOSNativeMAXProfile.compile(", "rawFiles = try ignored("},
		{"profile: selectedProfile, startLayer: start)", "profile: selectedProfile, startLayer: \"off\")"},
		{"LibboxRouterCompileMAXProfile(mode, assets, metadata, &failure)", "fakeGraph(mode)"},
		{"LibboxRouterCompileCompositeProfile(mode, assets, policy, start, &failure)", "fakeComposite(mode)"},
		{"LibboxRouterCompositeMultihopBase(source, mode, node, start, &failure)", "fakeProof(source)"},
		{"Data(captured.source.utf8)", "Data(captured.baseSource.utf8)"},
		{"rawFiles = [\"sing-box.json\": try JSONSerialization.data(withJSONObject: complete, options: [.sortedKeys])]", "rawFiles = captured.baseFiles"},
		{"RouterVPNMTUPolicy.libbox(composedFiles, profile: selectedProfile)", "RouterVPNMTUPolicy.libbox(rawFiles, profile: selectedProfile)"},
		{"var compositionRoot = root", "var compositionRoot: [String: Any] = [:]"},
		{"return LibboxCompilation(files: files, nodeID: expectedNodeID,", "return LibboxCompilation(files: rawFiles, nodeID: expectedNodeID,"},
		{"let compiled = try compileLibbox(provider: provider, root: root, selectedProfile: selectedProfile)", "let compiled = try unownedGraph()"},
		{"let files = compiled.files, provenNodeID = compiled.nodeID", "let files = originalFiles, provenNodeID = compiled.nodeID"},
		{"engine.start(files: files, strict: strict)", "engine.start(files: rawFiles, strict: strict)"},
		{"proveSelectedNode(url: proofURL, expectedNodeID: provenNodeID", "pretendConnected(url: proofURL, expectedNodeID: provenNodeID"},
	}
	for _, ending := range []string{"\n", "\r\n"} {
		captured := strings.ReplaceAll(body, "\n", ending)
		if !appleSingleLayerDispatchIsOwned(captured) {
			t.Fatal("valid dispatch rejected due to checkout line endings")
		}
		for _, test := range cases {
			before := strings.ReplaceAll(test[0], "\n", ending)
			after := strings.ReplaceAll(test[1], "\n", ending)
			if strings.Count(captured, before) != 1 {
				t.Fatalf("negative control missing its unique anchor: %q", before)
			}
			if appleSingleLayerDispatchIsOwned(strings.Replace(captured, before, after, 1)) {
				t.Fatalf("unowned pipeline accepted: %s", before)
			}
		}
	}
}
