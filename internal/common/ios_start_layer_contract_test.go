package common

import (
	"strings"
	"testing"
)

func TestAppleStartLayerIsComposedByPacketTunnelAndXORFailsClosed(t *testing.T) {
	composer := repoFile(t, "ios/RouterVPN/PacketTunnel/IOSStartLayer.swift")
	for _, required := range []string{
		`static let aes = "aes-256-gcm"`,
		`static let aesXOR = "aes-256-gcm+xor-whitening"`,
		`static let aesMethod = "2022-blake3-aes-256-gcm"`,
		`private static let supportedRawModes: Set<String> = ["shadowsocks", "hysteria2", "naive-h2", "naive-h3"]`,
		"Start Layer requires authenticated Shadowsocks 2022 BLAKE3 AES-256-GCM",
		"AES-256-GCM + XOR whitening is not available on iOS until PacketTunnel owns a protected local whitening relay",
		"XOR is never counted as encryption or silently ignored",
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
		"let rawFiles = try layeredProfile(root, rawProfileID: rawProfileID)",
		"let files = try IOSStartLayer.apply(root: root, selectedProfile: selectedProfile, files: rawFiles, rawProfileID: rawProfileID)",
		"try IOSStartLayer.validateExternal(profile: selectedProfile)",
		"try engine.start(files: files, strict: strict)",
		"proveSelectedNode(url: proofURL, expectedNodeID: expectedNodeID",
	} {
		if !strings.Contains(provider, required) {
			t.Fatalf("PacketTunnel does not enforce iOS Start Layer runtime truth: missing %q", required)
		}
	}

	selector := repoFile(t, "ios/RouterVPN/App/IOSRuntimeSelection.swift")
	for _, required := range []string{
		`private static let startLayerRawModes: Set<String> = ["shadowsocks", "hysteria2", "naive-h2", "naive-h3"]`,
		"try validateStartLayer(bundle: bundle, rawProfileID: rawProfileID)",
		"try validateStartLayer(bundle: bundle, rawProfileID: \"wg\")",
		"Start Layer AES-256-GCM requires an iOS Libbox raw mode",
		"AES-256-GCM + XOR whitening is unavailable on iOS until PacketTunnel owns a protected local whitening relay",
		"XOR is never counted as encryption or silently ignored",
	} {
		if !strings.Contains(selector, required) {
			t.Fatalf("iOS runtime selector can choose an engine that cannot honor Start Layer: missing %q", required)
		}
	}

	settings := repoFile(t, "ios/RouterVPN/App/IOSProfileSettingsView.swift")
	for _, required := range []string{
		`@State private var startLayer = "off"`,
		"AES-256-GCM — authenticated Libbox modes",
		"AES-256-GCM + XOR whitening — unavailable on iOS",
		"protected local whitening relay",
		"XOR is obfuscation only and is never counted as encryption",
		`startLayer = (p.startLayer ?? "off").lowercased()`,
		"p.startLayer = startLayer",
		`startLayer == "aes-256-gcm+xor-whitening"`,
		"AES+XOR cannot be saved as iOS-runnable",
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
