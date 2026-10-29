package mobiletor

import (
	"encoding/json"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"router-vpn/internal/mobilemultihop"
)

func desktopDynamicProfile(lines []string) map[string]any {
	p := desktopProfile()
	if len(lines) == 0 {
		p["external"] = map[string]any{"protocol": "tor"}
	} else {
		block := p["external"].(map[string]any)["tor_bridge"].(map[string]any)
		block["transport"], block["bridges"] = "custom", append([]string(nil), lines...)
	}
	return p
}

func TestDesktopPhysicalBrokerCapturesExactGraphAndBootstrap(t *testing.T) {
	for name, bridges := range map[string][]string{
		"plain": nil, "meek": {meekBridge}, "snowflake": {desktopProtectionSnowflakeBridge},
		"webtunnel": {desktopProtectionWebTunnelBridge},
		"mixed":     {obfs4Bridge, meekBridge, desktopProtectionSnowflakeBridge, desktopProtectionWebTunnelBridge},
	} {
		for _, kill := range []string{"on-connect", "always"} {
			for _, protocol := range []string{"tcp", "dot", "doh"} {
				t.Run(name+"/"+kill+"/"+protocol, func(t *testing.T) {
					profile := desktopDynamicProfile(bridges)
					profile["kill_switch_policy"], profile["kill_switch"] = kill, true
					profile["dns_protocol"], profile["dns_port"], profile["dns_server_name"] = protocol, 5443, "exact-resolver.example"
					source := torHostEncode(t, profile)
					if err := ValidateDesktopBridgeProfileForOS(source, "linux"); err != nil {
						t.Fatal(err)
					}
					policy := desktopPolicy(t, profile, "linux")
					meta := policy.Metadata()
					if !policy.PhysicalBroker() || !meta.PhysicalBroker || meta.KillSwitchPolicy != kill || meta.EntryID != "" || policy.Predecessor() != nil || policy.ServerPolicy() != nil {
						t.Fatal("Linux Direct graph lost its socket owner or borrowed another path")
					}
					graph, err := profileObject(policy.Config(), 4<<20)
					if err != nil {
						t.Fatal(err)
					}
					physical := torHostTagged(t, graph["outbounds"], DesktopPhysicalOutboundTag)
					if len(graph["outbounds"].([]any)) != 2 || physical["type"] != DesktopPhysicalOutboundType ||
						physical["session_id"] != meta.SessionID || physical["source_sha256"] != meta.SourceSHA256 || len(physical) != 4 {
						t.Fatal("dynamic physical outbound lost exact identity or acquired a default dialer")
					}
					servers := graph["dns"].(map[string]any)["servers"]
					selected, bootstrap := torHostTagged(t, servers, profileDNS), torHostTagged(t, servers, bootstrapDNS)
					if selected["detour"] != ProfileOutboundTag || bootstrap["detour"] != DesktopPhysicalOutboundTag || selected["server"] != "9.9.9.9" || bootstrap["server"] != selected["server"] || bootstrap["server_port"] != json.Number("5443") {
						t.Fatal("selected DNS or its bootstrap bypassed the exact path or substituted a resolver")
					}
					observer := graph["services"].([]any)[0].(map[string]any)
					if observer["physical_broker"] != true || observer["session_id"] != meta.SessionID || observer["source_sha256"] != meta.SourceSHA256 {
						t.Fatal("native factory is not mandatory before network activation")
					}
					destinations, err := policy.PhysicalDestinations()
					if err != nil || len(destinations) < 1 || destinations[0] != (mobilemultihop.PhysicalEgress{Host: "9.9.9.9", Port: 5443, Network: "tcp"}) {
						t.Fatal("exact selected DNS tuple was lost", err)
					}
					for _, row := range destinations {
						if row.Host == "192.0.2.2" || row.Host == "192.0.2.3" || row.Host == "192.0.2.4" {
							t.Fatal("dynamic placeholder acquired a physical exception")
						}
					}
					destinations[0].Host = "10.99.0.53"
					again, _ := policy.PhysicalDestinations()
					if again[0].Host != "9.9.9.9" {
						t.Fatal("caller changed captured physical destinations")
					}
					directory := filepath.Join(t.TempDir(), "capture")
					capture, err := NewDesktopBridgeCapture(source, desktopSession, desktopIsolation, "linux", filepath.Join(t.TempDir(), "tor"), directory)
					if err != nil {
						t.Fatal(err)
					}
					restored, err := DecodeDesktopBridgeCapture(source, capture.JSON(), directory)
					if err != nil || !restored.Policy().PhysicalBroker() || restored.Digests() != capture.Digests() || restored.Policy().Config() != policy.Config() {
						t.Fatal("private native capture changed its mandatory physical owner", err)
					}
					for _, target := range []string{"darwin", "windows"} {
						if ValidateDesktopBridgeProfileForOS(source, target) == nil {
							t.Fatal("another platform advertised the Linux socket guardian", target)
						}
						if got, err := NewDesktopBridgePolicy(source, desktopSession, desktopIsolation, target); err == nil || got != nil {
							t.Fatal("another platform compiled unowned strict dynamic sockets", target)
						}
					}
				})
			}
		}
	}
}

func TestDesktopPhysicalBrokerRetainsOnlySelectedLiteralPrivateExceptions(t *testing.T) {
	bridge := strings.Replace(desktopProtectionSnowflakeBridge, "https://broker.example/", "https://10.7.0.11:8443/", 1)
	bridge = strings.Replace(bridge, "front=front.example", "front=10.7.0.12", 1)
	bridge = strings.Replace(bridge, "ice=stun:stun.example:3478", "ice=stun:10.7.0.13:3456,stuns:[fd70::13]:5348?transport=tcp", 1)
	web := strings.Replace(desktopProtectionWebTunnelBridge, "https://tunnel.example/owned", "https://[fd70::14]:9443/owned", 1)
	policy := desktopPolicy(t, desktopDynamicProfile([]string{bridge, web}), "linux")
	got, err := policy.PhysicalDestinations()
	want := []mobilemultihop.PhysicalEgress{{Host: "9.9.9.9", Port: 5353, Network: "tcp"},
		{Host: "10.7.0.11", Port: 8443, Network: "tcp"}, {Host: "10.7.0.12", Port: 8443, Network: "tcp"},
		{Host: "10.7.0.13", Port: 3456, Network: "udp"}, {Host: "fd70::13", Port: 5348, Network: "tcp"},
		{Host: "fd70::14", Port: 9443, Network: "tcp"}}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatal("literal selected transport/port exceptions changed", got, err)
	}
}

func TestDesktopPhysicalBrokerNeverBorrowsProjectionOffOrFixedAuthority(t *testing.T) {
	for _, target := range []string{"linux", "darwin", "windows"} {
		p := desktopDynamicProfile([]string{meekBridge})
		p["kill_switch_policy"], p["kill_switch"], p["physical_broker"] = "off", false, true
		policy := desktopPolicy(t, p, target)
		if policy.PhysicalBroker() || strings.Contains(policy.Config(), DesktopPhysicalOutboundType) {
			t.Fatal("caller-owned marker silently changed Off into another policy")
		}
		if destinations, err := policy.PhysicalDestinations(); err == nil || destinations != nil {
			t.Fatal("Off policy acquired native socket authority")
		}
		fixed := desktopPolicy(t, desktopProfile(), target)
		if fixed.PhysicalBroker() || strings.Contains(fixed.Config(), DesktopPhysicalOutboundType) {
			t.Fatal("fixed obfs4 acquired unrelated dynamic authority")
		}
	}
	p := desktopDynamicProfile([]string{meekBridge})
	p["desktop_physical_egress"] = []any{map[string]any{"host": "9.9.9.9", "port": 5353, "network": "tcp"}}
	if policy, err := NewDesktopBridgePolicy(torHostEncode(t, p), desktopSession, desktopIsolation, "linux"); err == nil || policy != nil {
		t.Fatal("dynamic sockets acquired a destination-wide exemption")
	}
}
