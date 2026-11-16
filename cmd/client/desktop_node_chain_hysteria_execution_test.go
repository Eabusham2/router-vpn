package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"router-vpn/internal/common"
	"router-vpn/internal/mobilemultihop"
)

// Actual saved paired profiles, raw packet keys and Hysteria TLS/Salamander
// inputs reach the shipping compiler. No provider or native connection is
// synthesized here; public lifecycle tests explicitly model the child/kernel.
func desktopHysteriaExecutionProfiles(t *testing.T, count int) (*app, []common.MultihopNodeSelection) {
	t.Helper()
	a, nodes := desktopNodeChainCaptureFixture(t, count)
	modes := make([]string, count)
	for i := range modes {
		modes[i] = []string{"wg", "awg2-fast", "awg2-strong"}[i%3]
	}
	modes[count-1] = "shadowsocks"
	installOrderedAWGAssets(t, a, nodes, modes, "off")
	for i := range a.profiles.Profiles {
		p := &a.profiles.Profiles[i]
		p.KillSwitch, p.KillSwitchPolicy = true, "on-connect"
		// Eight nested packet members retain the same explicit provider capacity
		// used by existing long paired source fixtures.
		for _, mode := range []string{"wg", "awg2-fast", "awg2-strong"} {
			for _, name := range []string{"wg.conf", "wg-socks.conf", "awg.conf", "awg-socks.conf"} {
				path := filepath.Join(clientRoot(a), "generated", p.ID, mode, name)
				raw, err := os.ReadFile(path)
				if os.IsNotExist(err) {
					continue
				}
				if err != nil {
					t.Fatal(err)
				}
				if err = os.WriteFile(path, []byte(strings.ReplaceAll(string(raw), "MTU = 2000", "MTU = 4096")), 0600); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
	final := &a.profiles.Profiles[count-1]
	ca, _ := nativeMultihopTrafficCertificate(t)
	graph, err := json.Marshal(map[string]any{
		"inbounds":  []any{map[string]any{"type": "tun", "auto_route": true, "strict_route": true}},
		"outbounds": []any{map[string]any{"type": "hysteria2", "tag": "proxy", "server": final.Endpoint, "server_port": 443, "password": "captured-hysteria-password", "obfs": map[string]any{"type": "salamander", "password": "captured-salamander-password"}, "tls": map[string]any{"enabled": true, "server_name": "exit-certificate.example", "certificate_path": "cert.pem"}}},
		"route":     map[string]any{"final": "proxy"},
	})
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(clientRoot(a), "generated", final.ID, "hysteria2")
	if err = os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	for name, raw := range map[string][]byte{"sing-box.json": graph, "cert.pem": []byte(ca)} {
		if err = os.WriteFile(filepath.Join(dir, name), raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	nodes[count-1].Mode = "hysteria2"
	final.MultihopNodes = append([]common.MultihopNodeSelection(nil), nodes...)
	return a, nodes
}

func desktopHysteriaExecutionLaunchFixture(t *testing.T, count int, target, _ string, _ int, _ ...string) (*app, *desktopNodeLaunch) {
	t.Helper()
	a, nodes := desktopHysteriaExecutionProfiles(t, count)
	selection, err := resolveDesktopNodeChainSelection(a.profiles.Profiles[count-1], a.profiles.Profiles, nodes, "local")
	if err != nil {
		t.Fatal(err)
	}
	selection, err = captureNativeNodeChainSelection(context.Background(), clientRoot(a), selection, []string{"hysteria2"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	launch, err := newDesktopNodeChainLaunch(selection, strings.Repeat("a", 32), target)
	if err != nil {
		t.Fatal(err)
	}
	return a, launch
}

func TestDesktopHysteriaExecutionOriginalPreparation(t *testing.T) {
	for _, target := range []string{"linux", "windows", "darwin"} {
		for _, count := range []int{2, 4, 8} {
			for _, choice := range []string{"server", "auto"} {
				t.Run(fmt.Sprintf("%s/%d/%s", target, count, choice), func(t *testing.T) {
					_, launch := desktopHysteriaExecutionLaunchFixture(t, count, target, "", 0)
					e, err := newDesktopNodeChainExecutionSource(launch.chain, choice)
					if err != nil {
						t.Fatal("original paired Hysteria preparation refused", err)
					}
					if e.physical == nil || e.connectPhysical != nil || e.socksPhysical != nil || e.openvpnPhysical != nil {
						t.Fatal("paired Hysteria borrowed a typed imported owner")
					}
					original, err := e.physical.OriginalDesktopPolicy()
					if err != nil || original != launch.chain.policy {
						t.Fatal("paired Hysteria replaced original physical policy", err)
					}
					var source mobilemultihop.NodeChainSource
					if json.Unmarshal([]byte(e.preparation.LocalSource()), &source) != nil || source.Schema != 1 || len(source.Nodes) != count || len(source.IdentitySources) != count {
						t.Fatal("paired Hysteria lost complete schema-one source")
					}
					proofs := launch.chain.policy.OriginalChain().ProofInventory()
					if proofs[count-1].Mode != "hysteria2" || proofs[count-1].StartLayer != "off" || proofs[count-1].NodeKind == "external" {
						t.Fatal("paired Hysteria final lost private Off proof")
					}
					for _, proof := range proofs {
						if proof.NodeID == "" {
							t.Fatal("paired identity omitted")
						}
					}
					_, metadata, physical, readErr := e.readPolicy()
					if readErr != nil || metadata.TargetOS != target || metadata.Mode != "hysteria2" || metadata.KillSwitchPolicy != "on-connect" || physical.SelectedDNS.Detour != mobilemultihop.SelectorTag || physical.SelectedDNS.Physical {
						t.Fatal("paired Hysteria changed selected DNS, protection or target", readErr)
					}
					if err = e.attach(launch); err != nil {
						t.Fatal(err)
					}
					if err = e.bound(launch); err != nil {
						t.Fatal(err)
					}
					if !strings.Contains(string(launch.config), "captured-hysteria-password") || !strings.Contains(string(launch.config), "captured-salamander-password") || !strings.Contains(string(launch.config), "exit-certificate.example") {
						t.Fatal("Hysteria original authentication or TLS source replaced")
					}
				})
			}
		}
	}
}

func TestDesktopHysteriaExecutionSourceRefusals(t *testing.T) {
	for _, fault := range []string{"final-layer", "duplicate-identity", "duplicate-id", "foreign-kind", "imported-prefix", "wrong-prefix", "wrong-final"} {
		t.Run(fault, func(t *testing.T) {
			a, nodes := desktopHysteriaExecutionProfiles(t, 4)
			selected, err := resolveDesktopNodeChainSelection(a.profiles.Profiles[3], a.profiles.Profiles, nodes, "local")
			if err != nil || !desktopHysteriaExecutionMembers(selected.Nodes, "server") {
				t.Fatal("original paired Hysteria shape refused", err)
			}
			changed := cloneDesktopNodeChainMembers(selected.Nodes)
			switch fault {
			case "final-layer":
				changed[3].Profile.StartLayer = "aes-256-gcm"
			case "duplicate-identity":
				changed[3].Profile.NodeProofID = changed[0].Profile.NodeProofID
			case "duplicate-id":
				changed[3].Profile.ID = changed[0].Profile.ID
			case "foreign-kind":
				changed[3].Profile.NodeKind = "external"
			case "imported-prefix":
				changed[2].Profile.NodeKind = "external"
			case "wrong-prefix":
				changed[1].Mode = "shadowsocks"
			case "wrong-final":
				changed[3].Mode = "shadowsocks"
			}
			if desktopHysteriaExecutionMembers(changed, "server") {
				t.Fatal("paired Hysteria accepted foreign source or final layer", fault)
			}
		})
	}
	for _, fault := range []string{"source", "physical"} {
		t.Run(fault, func(t *testing.T) {
			_, launch := desktopHysteriaExecutionLaunchFixture(t, 4, "windows", "", 0)
			e, err := newDesktopNodeChainExecutionSource(launch.chain, "server")
			if err != nil {
				t.Fatal(err)
			}
			if err = e.attach(launch); err != nil {
				t.Fatal(err)
			}
			if fault == "source" {
				e.preparation, err = mobilemultihop.ParseDesktopNodeChainExecutionPreparation(e.preparation.Source())
			} else {
				e.physical = &mobilemultihop.DesktopNodeChainExecutionPhysicalPolicy{}
			}
			if err != nil {
				t.Fatal(err)
			}
			if e.bound(launch) == nil {
				t.Fatal("paired Hysteria borrowed foreign original execution owner", fault)
			}
		})
	}
}

func TestDesktopHysteriaExecutionSavedProfileRetainsSource(t *testing.T) {
	for _, count := range []int{2, 4, 8} {
		for _, choice := range []string{"server", "auto"} {
			t.Run(fmt.Sprintf("%d/%s", count, choice), func(t *testing.T) {
				a, nodes := desktopHysteriaExecutionProfiles(t, count)
				response := postSetup(t, a, "/api/connection-profile/setup/save", map[string]any{"name": "Paired Hysteria execution", "mode": "hysteria2", "multihop_enabled": true, "multihop_execution": choice, "multihop_nodes": nodes})
				if response.Code != http.StatusOK {
					t.Fatalf("paired Hysteria Save %d: %s", response.Code, response.Body.String())
				}
				store, err := loadConnectionProfileStore(a)
				if err != nil || len(store.Profiles) != 1 {
					t.Fatal("missing saved paired Hysteria", err)
				}
				saved := store.Profiles[0]
				if saved.Prefs.MultihopExecution != choice || len(saved.NodeChain) != count || saved.NodeChain[count-1].Mode != "hysteria2" {
					t.Fatal("saved paired Hysteria changed choice or final")
				}
				for _, member := range saved.NodeChain {
					if member.External != nil || member.NodeProofID == "" {
						t.Fatal("saved paired identity replaced")
					}
				}
				for _, fault := range []string{"source", "identity", "final-layer"} {
					raw, _ := json.Marshal(saved)
					var changed connectionProfileRecord
					if json.Unmarshal(raw, &changed) != nil {
						t.Fatal("saved clone")
					}
					switch fault {
					case "source":
						changed.NodeChain[count-1].Sources[0].SHA256 = "foreign"
					case "identity":
						changed.NodeChain[count-1].NodeProofID = ""
					case "final-layer":
						changed.NodeChain[count-1].Preferences.StartLayer = "aes-256-gcm"
					}
					if validateSavedNodeChain(changed) == nil {
						t.Fatal("saved Hysteria admitted changed source", fault)
					}
				}
				response = postSetup(t, a, "/api/connection-profile/setup/load", map[string]any{"id": saved.ID})
				if response.Code != http.StatusOK {
					t.Fatalf("paired Hysteria Load %d: %s", response.Code, response.Body.String())
				}
				selected, _ := profileByID(a.profiles.Profiles, a.profiles.SelectedID)
				if !reflect.DeepEqual(selected.MultihopNodes, nodes) || selected.MultihopExecution != choice || a.cmd != nil || a.state.Connected {
					t.Fatal("Load replaced original path or fabricated connection")
				}
				response = postSetup(t, a, "/api/connection-profile/setup/update", map[string]any{"id": saved.ID, "name": "Updated paired Hysteria", "mode": "hysteria2", "multihop_enabled": true, "multihop_execution": choice, "multihop_nodes": nodes})
				if response.Code != http.StatusOK {
					t.Fatal("paired Hysteria Update", response.Code, response.Body.String())
				}
				after, err := loadConnectionProfileStore(a)
				if err != nil || !reflect.DeepEqual(after.Profiles[0].NodeChain, saved.NodeChain) {
					t.Fatal("Update replaced original paired source", err)
				}
			})
		}
	}
}
