package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"router-vpn/internal/common"
)

func standardPreparedPolicyFixture(t *testing.T, protocol string) (common.RouterProfile, standardExit) {
	t.Helper()
	exit := validTestStandardExit(protocol)
	if protocol == "shadowsocks" {
		exit.Secret = testWGKey('s')
	}
	return common.RouterProfile{ID: "captured-policy", DNSMode: "custom", DNSProtocol: "tcp", DNSHost: "203.0.113.53", DNSPort: 5353,
		IPv6Mode: "off", HomeLANAccess: false, MTUPolicy: "auto", EffectiveMTU: 9000, KillSwitchPolicy: "off"}, exit
}

func readStandardPreparedPolicy(t *testing.T, directory string) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(directory, "sing-box.json"))
	if err != nil {
		t.Fatal(err)
	}
	var graph map[string]any
	if err := json.Unmarshal(raw, &graph); err != nil {
		t.Fatal(err)
	}
	return graph
}

func assertStandardPreparedDevicePolicy(t *testing.T, graph map[string]any, mtu int, blocked, ipv6off bool, dnsDetour string) {
	t.Helper()
	tun := graph["inbounds"].([]any)[0].(map[string]any)
	if tun["mtu"] != float64(mtu) || tun["auto_route"] != true || tun["strict_route"] != true {
		t.Fatal("prepared standard exit changed selected MTU or TUN route ownership", tun)
	}
	var hasLAN, hasIPv6, hasDNSPort bool
	for _, raw := range graph["route"].(map[string]any)["rules"].([]any) {
		rule := raw.(map[string]any)
		if rule["action"] == "reject" && rule["ip_version"] == float64(6) {
			hasIPv6 = true
		}
		if rule["action"] == "reject" {
			if ranges, ok := rule["ip_cidr"].([]any); ok {
				for _, prefix := range ranges {
					if prefix == "192.168.0.0/16" {
						hasLAN = true
					}
				}
			}
		}
		if rule["action"] == "hijack-dns" && rule["port"] == float64(53) {
			hasDNSPort = true
		}
	}
	if hasLAN != blocked || hasIPv6 != ipv6off || !hasDNSPort {
		t.Fatalf("prepared standard exit lost captured LAN/IPv6 or pre-sniff DNS enforcement: LAN=%v IPv6=%v DNS=%v", hasLAN, hasIPv6, hasDNSPort)
	}
	dns := graph["dns"].(map[string]any)["servers"].([]any)[0].(map[string]any)
	host := "203.0.113.53"
	if dnsDetour == "entry-wg" {
		host = "10.77.0.1"
	}
	if dns["server"] != host || dns["server_port"] != float64(5353) || dns["type"] != "tcp" || dns["detour"] != dnsDetour {
		t.Fatal("prepared standard exit replaced selected resolver, transport, port or path", dns)
	}
}

func TestStandardExitPreparationKeepsCapturedDevicePolicy(t *testing.T) {
	for _, protocol := range []string{"wireguard", "socks5", "http-connect", "https-connect", "shadowsocks", "hysteria2"} {
		for _, mode := range []string{"auto", "fixed"} {
			t.Run(protocol+"/"+mode, func(t *testing.T) {
				control, exit := standardPreparedPolicyFixture(t, protocol)
				control.MTUPolicy = mode
				wantMTU := 1280
				if mode == "fixed" {
					control.MTUPolicy, control.ManualMTU, wantMTU = "manual", 1320, 1320
				}
				before, _ := json.Marshal([]any{control, exit})
				directory, _, err := prepareDirectStandardExit(desktopAWGPrivateTestRoot(t), control, exit)
				if err != nil {
					t.Fatal(err)
				}
				graph := readStandardPreparedPolicy(t, directory)
				assertStandardPreparedDevicePolicy(t, graph, wantMTU, true, true, "custom-exit")
				original, _, err := directStandardExitRuntimeParts(exit)
				if protocol != "wireguard" {
					_, original, err = directStandardExitRuntimeParts(exit)
				}
				if err != nil {
					t.Fatal(err)
				}
				family := "outbounds"
				if protocol == "wireguard" {
					family = "endpoints"
				}
				actual := graph[family].([]any)[0].(map[string]any)
				for _, field := range []string{"private_key", "password", "username", "server", "server_port", "tls"} {
					left, _ := json.Marshal(original[field])
					right, _ := json.Marshal(actual[field])
					if !reflect.DeepEqual(left, right) {
						t.Fatal("device policy changed captured transport credentials or identity", field)
					}
				}
				after, _ := json.Marshal([]any{control, exit})
				if string(before) != string(after) {
					t.Fatal("preparation mutated saved source policy or exit")
				}
			})
		}
	}
}

func TestStandardExitPreparationPreservesEnabledLANAndIPv6(t *testing.T) {
	control, exit := standardPreparedPolicyFixture(t, "socks5")
	control.HomeLANAccess, control.IPv6Mode = true, "on"
	directory, _, err := prepareDirectStandardExit(desktopAWGPrivateTestRoot(t), control, exit)
	if err != nil {
		t.Fatal(err)
	}
	assertStandardPreparedDevicePolicy(t, readStandardPreparedPolicy(t, directory), 1280, false, false, "custom-exit")
}

func TestStandardExitPreparationRejectsInvalidAndIncompatiblePolicy(t *testing.T) {
	for _, fault := range []string{"small-fixed", "large-fixed", "unknown-mtu", "unknown-ipv6", "tcp-only-udp-dns", "tcp-only-h3-dns"} {
		t.Run(fault, func(t *testing.T) {
			control, exit := standardPreparedPolicyFixture(t, "http-connect")
			switch fault {
			case "small-fixed":
				control.MTUPolicy, control.ManualMTU = "manual", 1279
			case "large-fixed":
				control.MTUPolicy, control.ManualMTU = "manual", 9001
			case "unknown-mtu":
				control.MTUPolicy = "guess"
			case "unknown-ipv6":
				control.IPv6Mode = "guess"
			case "tcp-only-udp-dns":
				control.DNSProtocol = "udp"
			case "tcp-only-h3-dns":
				control.DNSMode, control.DNSProtocol, control.DNSServerName = "doh3", "h3", "selected.example.test"
			}
			root := desktopAWGPrivateTestRoot(t)
			if directory, _, err := prepareDirectStandardExit(root, control, exit); err == nil || directory != "" {
				t.Fatal("invalid selected policy became a runnable standard exit", directory, err)
			}
		})
	}
}

func TestStandardExitPreparationCompilesBothEntryKinds(t *testing.T) {
	for _, kind := range []string{"external", "router-vpn"} {
		t.Run(kind, func(t *testing.T) {
			root := desktopAWGPrivateTestRoot(t)
			control, exit := standardPreparedPolicyFixture(t, "socks5")
			var directory string
			var err error
			detour := "custom-exit"
			if kind == "external" {
				upstream := validTestStandardExit("socks5")
				upstream.ID, upstream.Server = "captured-entry", "198.51.100.20"
				entry, captureErr := desktopExternalCapture(control, upstream)
				if captureErr != nil {
					t.Fatal(captureErr)
				}
				entry.HomeLANAccess, entry.IPv6Mode = true, "on"
				directory, _, err = prepareExternalEntryStandardExit(root, control, entry, exit)
			} else {
				entry := common.RouterProfile{ID: "captured-router", NodeKind: "router-vpn", NodeProofID: strings.Repeat("c", 64), Endpoint: "198.51.100.20:51820", IPv6Mode: "on", HomeLANAccess: true, MTUPolicy: "auto",
					RouterAPI: "http://10.77.0.1:8787", APIToken: "captured-private-test-token", AdGuardIPv4: "10.77.0.1"}
				generated, genErr := nativeGeneratedDir(root, entry.ID, "wg")
				if genErr != nil {
					t.Fatal(genErr)
				}
				if err := os.MkdirAll(generated, 0700); err != nil {
					t.Fatal(err)
				}
				config := fmt.Sprintf("[Interface]\nPrivateKey = %s\nAddress = 10.66.0.2/32\nMTU = 1500\n[Peer]\nPublicKey = %s\nEndpoint = 198.51.100.20:51820\nAllowedIPs = 0.0.0.0/0, ::/0\n", testWGKey('c'), testWGKey('d'))
				if err := os.WriteFile(filepath.Join(generated, "wg.conf"), []byte(config), 0600); err != nil {
					t.Fatal(err)
				}
				control.DNSMode, control.DNSHost, detour = "home", "10.77.0.1", "entry-wg"
				directory, _, err = prepareNativeStandardExit(root, control, entry, exit)
			}
			if err != nil {
				t.Fatal(err)
			}
			assertStandardPreparedDevicePolicy(t, readStandardPreparedPolicy(t, directory), 1280, true, true, detour)
		})
	}
}
