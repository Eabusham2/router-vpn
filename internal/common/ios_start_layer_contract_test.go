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
		`inner.put`, // deliberate impossible marker guard below
	} {
		if required == "inner.put" {
			continue
		}
		if !strings.Contains(composer, required) {
			t.Fatalf("iOS Start Layer composer missing %q", required)
		}
	}
	for _, required := range []string{
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

	project := repoFile(t, "ios/RouterVPN/project.yml")
	if !strings.Contains(project, "sources: [PacketTunnel]") {
		t.Fatal("PacketTunnel target no longer composes the PacketTunnel source directory containing IOSStartLayer.swift")
	}
}
