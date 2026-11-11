package main

import (
	"context"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"router-vpn/internal/common"
	"router-vpn/internal/mobilemultihop"
)

func desktopNodeChainCaptureFixture(t *testing.T, count int) (*app, []common.MultihopNodeSelection) {
	t.Helper()
	a, nodes := savedNodeChainFixture(t, count)
	for i := range a.profiles.Profiles {
		p := &a.profiles.Profiles[i]
		p.MTUPolicy, p.ManualMTU, p.DAITAEnabled, p.SocksEnabled, p.JumboTUN = "auto", 0, false, false, false
		p.DNSMode, p.DNSProtocol, p.DNSHost, p.DNSPort = "home", "udp", "", 53
		p.DNSServerName, p.DNSPath = "", ""
		p.AdGuardIPv4 = "192.168.50.133"
		for _, name := range []string{"wg.conf", "wg-socks.conf"} {
			path := filepath.Join(clientRoot(a), "generated", p.ID, "wg", name)
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte(strings.Replace(string(raw), "[Interface]\n", "[Interface]\nMTU = 2000\n", 1)), 0600); err != nil {
				t.Fatal(err)
			}
		}
		ssPath := filepath.Join(clientRoot(a), "generated", p.ID, "shadowsocks", "sing-box.json")
		raw, err := os.ReadFile(ssPath)
		if err != nil {
			t.Fatal(err)
		}
		var graph map[string]any
		if err := json.Unmarshal(raw, &graph); err != nil {
			t.Fatal(err)
		}
		graph["inbounds"] = []any{map[string]any{"type": "tun", "auto_route": true, "strict_route": true}}
		graph["route"] = map[string]any{"final": "proxy"}
		raw, _ = json.Marshal(graph)
		if err := os.WriteFile(ssPath, raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	return a, nodes
}

func captureNodeChainTest(t *testing.T, a *app, nodes []common.MultihopNodeSelection) *desktopNodeChainCapture {
	t.Helper()
	control, _ := a.profileByIDLocked(a.profiles.SelectedID)
	capture, err := captureDesktopNodeChain(context.Background(), clientRoot(a), control, a.profiles.Profiles, nodes, "local", nil)
	if err != nil {
		t.Fatal(err)
	}
	return capture
}

func TestDesktopNodeChainCaptureOwnsCompleteOrderedSourceAndProjection(t *testing.T) {
	a, nodes := desktopNodeChainCaptureFixture(t, 3)
	capture := captureNodeChainTest(t, a, nodes)
	proofs := capture.chain.ProofInventory()
	if len(proofs) != 3 || len(capture.members) != 3 || capture.chain.SourceSHA256() == "" {
		t.Fatal("ordered capture omitted a selected prefix")
	}
	for i, proof := range proofs {
		if proof.ProfileID != nodes[i].ID || proof.Mode != nodes[i].Mode || proof.NodeID != a.profiles.Profiles[i].NodeProofID {
			t.Fatal("compiled prefix differs from original catalog order")
		}
	}
	if err := capture.currentContext(context.Background(), a); err != nil {
		t.Fatal(err)
	}
	// Persisted measurement readback is not a changed source preference. The
	// native restore separately captures the live original TUN's actual MTU.
	for i := range a.profiles.Profiles {
		a.profiles.Profiles[i].EffectiveMTU = 1300 + i
	}
	if err := capture.currentContext(context.Background(), a); err != nil {
		t.Fatal("measurement retired the ordered source:", err)
	}
	for _, target := range []string{"linux", "windows", "darwin"} {
		projected, err := capture.project(context.Background(), target, 0)
		if err != nil {
			t.Fatal(err)
		}
		input, err := projected.LaunchInput()
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := mobilemultihop.ParseNodeChainLaunchInput(input)
		if err != nil || parsed.SourceSHA256() != capture.chain.SourceSHA256() || parsed.ConfigSHA256() != projected.ConfigSHA256() || parsed.TargetOS() != target {
			t.Fatalf("projected child lost original ordered source: %v", err)
		}
		physical, err := parsed.PhysicalEgress()
		if err != nil || len(physical) == 0 {
			t.Fatalf("first prefix has no physical source: %v", err)
		}
		encoded, _ := json.Marshal(physical)
		for _, p := range a.profiles.Profiles[1:] {
			if strings.Contains(string(encoded), p.Endpoint) {
				t.Fatal("middle/final endpoint gained physical bypass ownership")
			}
		}
	}
	if current, err := capture.chain.LaunchInput(); err != nil || current != capture.input {
		t.Fatal("platform projection mutated original capture")
	}
}

func TestDesktopNodeChainCaptureRejectsStaleMiddleCatalogSourceAndOrder(t *testing.T) {
	for _, change := range []string{"credential", "dns", "mtu", "layer", "asset", "order", "removed", "duplicate-catalog", "cancelled"} {
		t.Run(change, func(t *testing.T) {
			a, nodes := desktopNodeChainCaptureFixture(t, 3)
			capture := captureNodeChainTest(t, a, nodes)
			ctx := context.Background()
			switch change {
			case "credential":
				a.profiles.Profiles[1].APIToken += "-relinked"
			case "dns":
				a.profiles.Profiles[1].DNSHost = "1.1.1.1"
			case "mtu":
				a.profiles.Profiles[1].MTUPolicy, a.profiles.Profiles[1].ManualMTU = "manual", 1400
			case "layer":
				a.profiles.Profiles[1].StartLayer = "aes-256-gcm"
			case "asset":
				path := filepath.Join(clientRoot(a), "generated", nodes[1].ID, "wg", "wg.conf")
				raw, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, append(raw, []byte("\n# changed middle source\n")...), 0600); err != nil {
					t.Fatal(err)
				}
			case "order":
				a.profiles.Profiles[2].MultihopNodes[0], a.profiles.Profiles[2].MultihopNodes[1] = a.profiles.Profiles[2].MultihopNodes[1], a.profiles.Profiles[2].MultihopNodes[0]
			case "removed":
				a.profiles.Profiles = append(a.profiles.Profiles[:1], a.profiles.Profiles[2:]...)
			case "duplicate-catalog":
				a.profiles.Profiles = append(a.profiles.Profiles, a.profiles.Profiles[1])
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			if err := capture.currentContext(ctx, a); err == nil {
				t.Fatal("stale ordered capture was accepted")
			}
			if capture.members[1].Profile.APIToken == "" || capture.members[1].Profile.APIToken != "private-api-1" {
				t.Fatal("catalog mutation replaced the original private member")
			}
		})
	}
}

func TestDesktopNodeChainLaterHostnameFailsBeforeAnyAmbientBootstrap(t *testing.T) {
	a, nodes := desktopNodeChainCaptureFixture(t, 3)
	a.profiles.Profiles[1].Endpoint = "middle.example.test"
	control := common.CloneRouterProfile(a.profiles.Profiles[2])
	calls := 0
	_, err := captureDesktopNodeChain(context.Background(), clientRoot(a), control, a.profiles.Profiles, nodes, "local", func(context.Context, string) ([]netip.Addr, error) {
		calls++
		return []netip.Addr{netip.MustParseAddr("203.0.113.30")}, nil
	})
	if err == nil || calls != 0 {
		t.Fatal("later transport hostname escaped through physical bootstrap")
	}
}

func TestDesktopNodeChainCaptureCopiesSavedSelectionBeforeProjection(t *testing.T) {
	a, nodes := desktopNodeChainCaptureFixture(t, 4)
	capture := captureNodeChainTest(t, a, nodes)
	original := capture.chain.ProofInventory()
	nodes[1].ID = "replacement"
	a.profiles.Profiles[1].HomeLANCIDRs = []string{"10.0.0.0/8"}
	if !reflect.DeepEqual(original, capture.chain.ProofInventory()) || capture.members[1].Profile.ID == "replacement" {
		t.Fatal("live selection mutated sealed forwarding order")
	}
}
