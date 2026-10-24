package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"router-vpn/internal/common"
	"router-vpn/internal/multihoprelay"
)

func desktopLayerProfile(t *testing.T, protocol, mode string) common.RouterProfile {
	t.Helper()
	exit := validTestStandardExit(protocol)
	if protocol == "shadowsocks" {
		exit.Secret = testWGKey('s')
	}
	exit.StartLayer = &common.ExternalStartLayer{Mode: mode, API: "http://10.77.0.1:8787", Transport: map[string]any{"type": "shadowsocks", "tag": "saved-layer", "server": exit.Server, "server_port": float64(8389), "method": "2022-blake3-aes-256-gcm", "password": testWGKey('l')}}
	exit.ResponseProbe = &common.ExternalResponseProbe{URL: "https://" + exit.Server + "/node-response", ServerName: "node.example"}
	profile, err := desktopExternalCapture(common.RouterProfile{DNSMode: "custom", DNSProtocol: "tcp", DNSHost: "203.0.113.53", DNSPort: 5353, IPv6Mode: "off", HomeLANAccess: false, MTUPolicy: "auto", EffectiveMTU: 9000}, exit)
	if err != nil {
		t.Fatal(err)
	}
	if err = common.NormalizeRouterProfile(&profile); err != nil {
		t.Fatal(err)
	}
	return profile
}

func TestDesktopExternalLayerUsesCapturedNativeTransportAndSavedDNS(t *testing.T) {
	for _, protocol := range []string{"shadowsocks", "hysteria2", "socks5", "http-connect", "https-connect"} {
		for _, mode := range []string{common.StartLayerAES256GCM, common.StartLayerAES256GCMXOR} {
			t.Run(protocol+"/"+mode, func(t *testing.T) {
				profile := desktopLayerProfile(t, protocol, mode)
				exit, err := standardExitFromExternalProfile(profile)
				if err != nil {
					t.Fatal(err)
				}
				profile.External.StartLayer.Transport["password"] = "replacement"
				if exit.StartLayer.Transport["password"] != testWGKey('l') {
					t.Fatal("runtime capture shares editable private layer")
				}
				profile.External.StartLayer.Transport["password"] = testWGKey('l')
				dir, _, err := prepareDirectStandardExit(desktopAWGPrivateTestRoot(t), profile, exit)
				if err != nil {
					t.Fatal(err)
				}
				raw, err := os.ReadFile(filepath.Join(dir, "sing-box.json"))
				if err != nil {
					t.Fatal(err)
				}
				var graph map[string]any
				if json.Unmarshal(raw, &graph) != nil {
					t.Fatal("invalid native graph")
				}
				outbounds := graph["outbounds"].([]any)
				inner := taggedRuntimeItem(outbounds, "custom-exit")
				outer := taggedRuntimeItem(outbounds, multihoprelay.ExitStartLayerTag)
				if inner == nil || outer == nil || inner["server"] != "10.77.0.1" || inner["detour"] != multihoprelay.ExitStartLayerTag || outer["server"] != exit.Server || outer["password"] != testWGKey('l') {
					t.Fatal("selected external encryption was ignored or moved to another host")
				}
				if _, exists := outer["detour"]; exists {
					t.Fatal("direct outer layer gained an unrelated upstream owner")
				}
				wantType := "shadowsocks"
				if mode == common.StartLayerAES256GCMXOR {
					wantType = "routervpn-aes-xor"
				}
				if outer["type"] != wantType {
					t.Fatal("selected whitening differs from the running graph")
				}
				dns := graph["dns"].(map[string]any)["servers"].([]any)[0].(map[string]any)
				if dns["server"] != "203.0.113.53" || dns["server_port"] != float64(5353) || dns["type"] != "tcp" || dns["detour"] != "custom-exit" {
					t.Fatal("layer compilation substituted selected DNS")
				}
				tun := graph["inbounds"].([]any)[0].(map[string]any)
				if tun["mtu"] != float64(1280) {
					t.Fatal("historical MTU became a new-path result")
				}
			})
		}
	}
}

func TestDesktopExternalLayerEntryWrapsOpenVPNBridgeWithoutAnotherSystemTunnel(t *testing.T) {
	for _, protocol := range []string{"shadowsocks", "socks5", "http-connect", "https-connect", "hysteria2"} {
		profile := desktopLayerProfile(t, protocol, common.StartLayerAES256GCMXOR)
		entry, err := standardExitFromExternalProfile(profile)
		if err != nil {
			t.Fatal(err)
		}
		graph, err := externalEntryBridgeConfig(entry, 1190)
		if err != nil {
			t.Fatal(err)
		}
		out := graph["outbounds"].([]any)
		inside, outside := taggedRuntimeItem(out, "external-entry"), taggedRuntimeItem(out, "routervpn-external-entry-start-layer")
		if inside == nil || outside == nil || inside["server"] != "10.77.0.1" || inside["detour"] != outside["tag"] || outside["server"] != entry.Server {
			t.Fatal("OpenVPN bridge lost its private upstream layer")
		}
		if len(graph["inbounds"].([]any)) != 1 || graph["inbounds"].([]any)[0].(map[string]any)["type"] != "mixed" {
			t.Fatal("entry bridge created a competing system tunnel")
		}
	}
}

func TestDesktopExternalLayersRetainDistinctEntryExitOwners(t *testing.T) {
	profile := desktopLayerProfile(t, "hysteria2", common.StartLayerAES256GCMXOR)
	exit, err := standardExitFromExternalProfile(profile)
	if err != nil {
		t.Fatal(err)
	}
	entry := desktopLayerProfile(t, "shadowsocks", common.StartLayerAES256GCM)
	entry.ID, entry.Endpoint = "private-entry", "203.0.113.11"
	entry.External.Shadowsocks.Server = entry.Endpoint
	entry.External.StartLayer.Transport["server"] = entry.Endpoint
	entry.External.StartLayer.Transport["password"] = testWGKey('e')
	entry.External.ResponseProbe.URL = "https://" + entry.Endpoint + "/node-response"
	dir, _, err := prepareExternalEntryStandardExit(desktopAWGPrivateTestRoot(t), profile, entry, exit)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "sing-box.json"))
	if err != nil {
		t.Fatal(err)
	}
	var graph map[string]any
	if json.Unmarshal(raw, &graph) != nil {
		t.Fatal("invalid native graph")
	}
	items := graph["outbounds"].([]any)
	entryInner := taggedRuntimeItem(items, "external-entry")
	entryOuter := taggedRuntimeItem(items, "routervpn-external-entry-start-layer")
	exitOuter := taggedRuntimeItem(items, multihoprelay.ExitStartLayerTag)
	if entryInner == nil || entryOuter == nil || exitOuter == nil || entryInner["detour"] != entryOuter["tag"] || exitOuter["detour"] != "external-entry" || entryOuter["server"] != entry.Endpoint || exitOuter["server"] != exit.Server || entryOuter["password"] != testWGKey('e') || exitOuter["password"] != testWGKey('l') {
		t.Fatal("entry and exit layers lost their separate private owners")
	}
	if _, exists := entryOuter["detour"]; exists {
		t.Fatal("physical entry layer detoured into the exit")
	}
}

func TestDesktopExternalLayerNeedsVerifiedCompleteNativeEngine(t *testing.T) {
	env := desktopExternalEngineEnvironment([]string{"HOMEVPN_STANDARD_ENGINE=stock", "homevpn_native_controller=untrusted", "HOMEVPN_AMNEZIA_PACKAGE=other", "KEPT=1"}, true, true)
	joined := strings.Join(env, "\n")
	if strings.Count(strings.ToUpper(joined), "HOMEVPN_STANDARD_ENGINE=") != 1 || !strings.Contains(joined, "HOMEVPN_STANDARD_ENGINE=native") || strings.Contains(joined, "untrusted") || strings.Contains(joined, "HOMEVPN_AMNEZIA_PACKAGE=") || !strings.Contains(joined, "HOMEVPN_NATIVE_CONTROLLER=") || !strings.Contains(joined, "HOMEVPN_NATIVE_PACKAGE=") {
		t.Fatal("layered desktop runtime could use an unverified or stale engine")
	}
}

func TestDesktopCapturedPrivateLayersAndAWGParametersCannotAliasReplacementNode(t *testing.T) {
	profile := desktopLayerProfile(t, "shadowsocks", common.StartLayerAES256GCM)
	clone := cloneRouterProfile(profile)
	profile.External.StartLayer.Transport["password"] = "replacement"
	profile.External.ResponseProbe.URL = "https://203.0.113.11/other"
	if clone.External.StartLayer.Transport["password"] != testWGKey('l') || clone.External.ResponseProbe.URL == profile.External.ResponseProbe.URL {
		t.Fatal("captured layer/probe is mutable through replacement node")
	}
	awg := desktopAWGProfile(t)
	copy := cloneRouterProfile(awg)
	awg.External.AmneziaWG.Parameters["s4"] = "0"
	awg.External.AmneziaWG.Addresses[0] = "10.1.1.2/32"
	if copy.External.AmneziaWG.Parameters["s4"] != "32" || reflect.DeepEqual(copy.External.AmneziaWG.Addresses, awg.External.AmneziaWG.Addresses) {
		t.Fatal("captured AWG identity or padding was mutated by replacement selection")
	}
}

func TestDesktopConnectionProfileCapturesLayerChoiceWithoutPrivateKey(t *testing.T) {
	profile := desktopLayerProfile(t, "shadowsocks", common.StartLayerAES256GCM)
	capture, err := snapshotExternalConnectionPolicy(profile)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(capture)
	if err != nil || strings.Contains(string(raw), testWGKey('l')) || strings.Contains(string(raw), "transport") || capture.StartLayer != common.StartLayerAES256GCM {
		t.Fatal("connection profile lost selection or copied linked private material")
	}
	profile.External.StartLayer.Transport["password"] = testWGKey('n')
	restored, err := capture.apply(profile)
	if err != nil || restored.External.StartLayer.Transport["password"] != testWGKey('n') {
		t.Fatal("restore overwrote rotated linked-layer credentials", err)
	}
	profile.StartLayer, profile.External.StartLayer.Mode = common.StartLayerAES256GCMXOR, common.StartLayerAES256GCMXOR
	if _, err := capture.apply(profile); err == nil {
		t.Fatal("restore accepted a differently provisioned private layer")
	}
}

func TestPublicExternalLayerNeverExposesPrivateProvision(t *testing.T) {
	p := desktopLayerProfile(t, "shadowsocks", common.StartLayerAES256GCM)
	raw, err := json.Marshal(publicProfileFor(p))
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{testWGKey('l'), testWGKey('s'), "10.77.0.1:8787", `"transport":`, `"response_probe":`, `"server_peer":`} {
		if strings.Contains(string(raw), secret) {
			t.Fatal("public node view exposed a private layer, transport or endpoint credential")
		}
	}
	public := publicProfileFor(p)
	if public.External == nil || !public.External.HasResponseProbe || public.External.HasServerPeer {
		t.Fatal("public proxy readiness is inconsistent with its captured private provisioning")
	}
}
