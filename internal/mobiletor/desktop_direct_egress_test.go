package mobiletor

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"router-vpn/internal/common"
	"router-vpn/internal/mobilemultihop"
)

func directObfs4Source(t *testing.T, count int, transport string) (map[string]any, Plan, []mobilemultihop.PhysicalEgress) {
	t.Helper()
	lines := make([]string, count)
	want := make([]mobilemultihop.PhysicalEgress, count)
	for i := range lines {
		host, endpoint := fmt.Sprintf("203.0.113.%d", i+30), fmt.Sprintf("203.0.113.%d:%d", i+30, 443+i)
		if i%2 == 1 {
			host, endpoint = fmt.Sprintf("2001:db8::%x", i+30), fmt.Sprintf("[2001:db8::%x]:%d", i+30, 443+i)
		}
		lines[i] = strings.Replace(obfs4Bridge, "198.51.100.9:443", endpoint, 1)
		want[i] = mobilemultihop.PhysicalEgress{Host: host, Port: 443 + i, Network: "tcp"}
	}
	plan, err := NewPlan(common.ExternalTorBridgeConfig{Transport: transport, Bridges: lines})
	if err != nil {
		t.Fatal(err)
	}
	profile := desktopProfile()
	block := profile["external"].(map[string]any)["tor_bridge"].(map[string]any)
	block["transport"], block["bridges"] = transport, lines
	profile["desktop_physical_egress"] = want
	return profile, plan, want
}

func TestDesktopDirectPhysicalEgressCapturesEveryFixedBridge(t *testing.T) {
	for count := 1; count <= 8; count++ {
		for _, transport := range []string{"obfs4", "custom"} {
			profile, plan, want := directObfs4Source(t, count, transport)
			got, err := DesktopDirectPhysicalEgress(plan)
			if err != nil || !reflect.DeepEqual(got, want) {
				t.Fatal("fixed source lost an exact TCP socket", count, transport, got, err)
			}
			for _, kill := range []string{"off", "on-connect", "always"} {
				profile["kill_switch_policy"] = kill
				source := torHostEncode(t, profile)
				for _, target := range []string{"linux", "darwin", "windows"} {
					policy, err := NewDesktopBridgePolicy(source, desktopSession, desktopIsolation, target)
					if err != nil || policy.Profile() != source || policy.Predecessor() != nil || policy.Metadata().EntryID != "" || policy.Metadata().KillSwitchPolicy != kill {
						t.Fatal("fixed Direct compiler borrowed a predecessor or changed source", count, transport, kill, target, err)
					}
					actual, err := policy.Plan()
					if err != nil || !reflect.DeepEqual(actual, plan) {
						t.Fatal("fixed Direct compiler dropped a bridge credential", err)
					}
				}
			}
		}
	}
}

func TestDesktopDirectPhysicalEgressDoesNotTrustExportedPlanFields(t *testing.T) {
	for _, field := range []string{"target", "transport", "argument", "line", "empty", "oversized"} {
		_, plan, _ := directObfs4Source(t, 2, "obfs4")
		switch field {
		case "target":
			plan.Bridges[0].Target = "8.8.8.8:53"
		case "transport":
			plan.Bridges[0].Transport = "snowflake"
		case "argument":
			plan.Bridges[0].Arguments["cert"] = "other-relay"
		case "line":
			plan.Bridges[0].Line = strings.Replace(plan.Bridges[0].Line, "203.0.113.30", "8.8.8.8", 1)
		case "empty":
			plan.Bridges = nil
		case "oversized":
			for len(plan.Bridges) <= 8 {
				plan.Bridges = append(plan.Bridges, plan.Bridges[0])
			}
		}
		if got, err := DesktopDirectPhysicalEgress(plan); err == nil || got != nil {
			t.Fatal("mutable convenience field granted physical authority", field, got)
		}
	}
}

func TestDesktopDirectPhysicalEgressPreservesSharedSocketCredentials(t *testing.T) {
	lines := []string{obfs4Bridge, strings.Replace(obfs4Bridge, "0123456789ABCDEF0123456789ABCDEF01234567", "1123456789ABCDEF0123456789ABCDEF01234567", 1)}
	plan, err := NewPlan(common.ExternalTorBridgeConfig{Transport: "obfs4", Bridges: lines})
	if err != nil {
		t.Fatal(err)
	}
	got, err := DesktopDirectPhysicalEgress(plan)
	if err != nil || len(got) != 1 || got[0] != (mobilemultihop.PhysicalEgress{Host: "198.51.100.9", Port: 443, Network: "tcp"}) || len(plan.Bridges) != 2 || plan.Bridges[1].Line != lines[1] {
		t.Fatal("socket deduplication discarded credentials or widened physical permission", got, err)
	}
}

func TestDesktopDirectPhysicalEgressUsesTheNativePhysicalAddressBoundary(t *testing.T) {
	for _, host := range []string{"0.0.0.1", "224.0.0.1", "240.0.0.1", "255.255.255.255"} {
		// The generic bridge parser retains these literal inputs for transport
		// validation. They must never acquire physical firewall authority.
		line := strings.Replace(obfs4Bridge, "198.51.100.9", host, 1)
		plan, err := NewPlan(common.ExternalTorBridgeConfig{Transport: "obfs4", Bridges: []string{line}})
		if err != nil {
			t.Fatal("address-boundary fixture did not reach the actual fixed projection", host, err)
		}
		if result, err := DesktopDirectPhysicalEgress(plan); err == nil || result != nil {
			t.Fatal("non-unicast literal acquired a Direct physical exception", host, result)
		}
	}
}

func TestDesktopDirectPhysicalEgressRejectsChangedProjectionAndDynamicSources(t *testing.T) {
	base, _, _ := directObfs4Source(t, 2, "custom")
	source := torHostEncode(t, base)
	for name, change := range map[string]func(map[string]any){
		"missing":  func(p map[string]any) { delete(p, "desktop_physical_egress") },
		"port":     func(p map[string]any) { p["desktop_physical_egress"].([]any)[1].(map[string]any)["port"] = 53 },
		"udp":      func(p map[string]any) { p["desktop_physical_egress"].([]any)[1].(map[string]any)["network"] = "udp" },
		"resolver": func(p map[string]any) { p["desktop_physical_egress"].([]any)[1].(map[string]any)["host"] = "9.9.9.9" },
		"duplicate": func(p map[string]any) {
			p["desktop_physical_egress"] = append(p["desktop_physical_egress"].([]any), p["desktop_physical_egress"].([]any)[0])
		},
		"partial": func(p map[string]any) { p["desktop_physical_egress"] = p["desktop_physical_egress"].([]any)[:1] },
		"order": func(p map[string]any) {
			rows := p["desktop_physical_egress"].([]any)
			rows[0], rows[1] = rows[1], rows[0]
		},
		"unknown": func(p map[string]any) {
			p["desktop_physical_egress"].([]any)[0].(map[string]any)["role"] = "router-entry"
		},
		"private-source": func(p map[string]any) {
			p["external"].(map[string]any)["tor_bridge"].(map[string]any)["bridges"].([]any)[0] = strings.Replace(obfs4Bridge, "198.51.100.9", "192.168.50.1", 1)
		},
		"dynamic-source": func(p map[string]any) {
			p["external"].(map[string]any)["tor_bridge"].(map[string]any)["bridges"].([]any)[1] = meekBridge
		},
		"borrowed-entry": func(p map[string]any) {
			p["multihop_enabled"], p["multihop_entry_id"], p["multihop_exit_id"] = true, "private-entry", p["id"]
		},
	} {
		for _, target := range []string{"linux", "darwin", "windows"} {
			profile, _ := profileObject(source, 256<<10)
			change(profile)
			if policy, err := NewDesktopBridgePolicy(torHostEncode(t, profile), desktopSession, desktopIsolation, target); err == nil || policy != nil {
				t.Fatal("changed Direct physical authority was admitted", name, target)
			}
		}
	}
	for _, lines := range [][]string{nil, {meekBridge}, {desktopProtectionSnowflakeBridge}, {desktopProtectionWebTunnelBridge}, {obfs4Bridge, meekBridge}, {obfs4Bridge, desktopProtectionSnowflakeBridge, desktopProtectionWebTunnelBridge}} {
		plan := Plan{}
		if len(lines) != 0 {
			var err error
			plan, err = NewPlan(common.ExternalTorBridgeConfig{Transport: "custom", Bridges: lines})
			if err != nil {
				t.Fatal(err)
			}
		}
		if _, err := DesktopDirectPhysicalEgress(plan); err == nil {
			t.Fatal("unsupported dynamic path acquired fixed Direct authority", lines)
		}
	}
}
