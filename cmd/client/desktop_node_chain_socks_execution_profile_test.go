package main

import (
	"encoding/json"
	"net/http"
	"reflect"
	"testing"

	"router-vpn/internal/common"
)

func TestDesktopSOCKSExecutionSelectionKeepsExactTrio(t *testing.T) {
	for _, mode := range []string{"wg", "awg2-fast", "awg2-strong"} {
		for _, choice := range []string{"server", "auto"} {
			t.Run(mode+"/"+choice, func(t *testing.T) {
				a, nodes := desktopSOCKSCaptureFixture(t, mode, "password", "off")
				selection, err := resolveDesktopNodeChainSelection(a.profiles.Profiles[2], a.profiles.Profiles, nodes, choice)
				if err != nil || !desktopSOCKSTrioExecutionMembers(selection.Nodes, choice) {
					t.Fatal("original SOCKS execution trio refused", err)
				}
				if _, err := resolveDesktopNodeChainSOCKSMembers(a.profiles.Profiles[2], a.profiles.Profiles, nodes, choice); err == nil {
					t.Fatal("Local SOCKS compiler accepted execution authority")
				}
				for _, fault := range []string{"long", "final-layer", "entry-layer", "wrong-final", "paired-middle", "duplicate-proof", "duplicate-id", "partial-auth", "hostname", "CONNECT-family", "middle-pairing"} {
					changed := cloneDesktopNodeChainMembers(selection.Nodes)
					switch fault {
					case "long":
						changed = append(changed[:1], append([]desktopNodeChainMember{changed[0]}, changed[1:]...)...)
					case "final-layer":
						changed[2].Profile.StartLayer = "aes-256-gcm"
					case "entry-layer":
						changed[0].Profile.StartLayer = "AES-256-GCM"
					case "wrong-final":
						changed[2].Mode = "hysteria2"
					case "paired-middle":
						changed[1].Profile.NodeKind = "router-vpn"
					case "duplicate-proof":
						changed[2].Profile.NodeProofID = changed[0].Profile.NodeProofID
					case "duplicate-id":
						changed[2].Profile.ID = changed[0].Profile.ID
					case "partial-auth":
						changed[1].Profile.External.SOCKS5.Password = ""
					case "hostname":
						changed[1].Profile.External.SOCKS5.Host, changed[1].Profile.Endpoint = "proxy.example", "proxy.example"
					case "CONNECT-family":
						changed[1].Mode, changed[1].Profile.External.Protocol = "http-connect", "http-connect"
					case "middle-pairing":
						changed[1].Profile.APIToken = "foreign-paired-token"
					}
					if desktopSOCKSTrioExecutionMembers(changed, choice) {
						t.Fatal("SOCKS execution admitted changed source shape", fault)
					}
				}
			})
		}
	}
}

func TestDesktopSOCKSExecutionSavedProfileKeepsCompleteSource(t *testing.T) {
	testDesktopSOCKSExecutionSavedProfile(t, 3)
}
func testDesktopSOCKSExecutionSavedProfile(t *testing.T, count int) {
	for _, requested := range []string{"server", "auto"} {
		t.Run(requested, func(t *testing.T) {
			a, nodes := desktopSOCKSPrefixCaptureFixture(t, count-2, "wg", "password", "off")
			response := postSetup(t, a, "/api/connection-profile/setup/save", map[string]any{"name": "Original SOCKS execution", "mode": "shadowsocks", "multihop_enabled": true, "multihop_execution": requested, "multihop_nodes": nodes})
			if response.Code != http.StatusOK {
				t.Fatalf("SOCKS Save %d: %s", response.Code, response.Body.String())
			}
			store, err := loadConnectionProfileStore(a)
			if err != nil || len(store.Profiles) != 1 {
				t.Fatal("SOCKS saved source absent", err)
			}
			saved := store.Profiles[0]
			if saved.Prefs.MultihopExecution != requested || len(saved.NodeChain) != count || saved.NodeChain[count-2].NodeProofID != "" || saved.NodeChain[count-2].External == nil || saved.NodeChain[count-2].External.Protocol != "socks5" {
				t.Fatal("SOCKS Save changed original source family")
			}
			for _, fault := range []string{"long", "final-layer", "middle-kind", "middle-protocol", "source-digest"} {
				raw, _ := json.Marshal(saved)
				var changed connectionProfileRecord
				if json.Unmarshal(raw, &changed) != nil {
					t.Fatal("saved fixture clone")
				}
				switch fault {
				case "long":
					changed.NodeChain = append(changed.NodeChain[:1], append([]connectionProfileNodeChainCapture{changed.NodeChain[0]}, changed.NodeChain[1:]...)...)
					changed.Prefs.MultihopNodes = append(changed.Prefs.MultihopNodes[:1], append([]common.MultihopNodeSelection{changed.Prefs.MultihopNodes[0]}, changed.Prefs.MultihopNodes[1:]...)...)
				case "final-layer":
					changed.NodeChain[count-1].Preferences.StartLayer = "aes-256-gcm"
				case "middle-kind":
					changed.NodeChain[count-2].NodeKind = "router-vpn"
				case "middle-protocol":
					changed.NodeChain[count-2].External.Protocol = "http-connect"
				case "source-digest":
					changed.NodeChain[count-2].Sources[0].SHA256 = "foreign"
				}
				if validateSavedNodeChain(changed) == nil {
					t.Fatal("saved SOCKS execution admitted changed source", fault)
				}
			}
			response = postSetup(t, a, "/api/connection-profile/setup/load", map[string]any{"id": saved.ID})
			if response.Code != http.StatusOK {
				t.Fatalf("SOCKS Load %d: %s", response.Code, response.Body.String())
			}
			var body map[string]any
			if json.Unmarshal(response.Body.Bytes(), &body) != nil || body["multihop_execution"] != requested || a.cmd != nil || a.state.Connected {
				t.Fatal("SOCKS Load changed choice or fabricated connection")
			}
			final, _ := profileByID(a.profiles.Profiles, a.profiles.SelectedID)
			if !reflect.DeepEqual(final.MultihopNodes, nodes) || final.MultihopExecution != requested {
				t.Fatal("SOCKS Load lost original ordered members")
			}
			response = postSetup(t, a, "/api/connection-profile/setup/update", map[string]any{"id": saved.ID, "name": "Updated SOCKS choice", "mode": "shadowsocks", "multihop_enabled": true, "multihop_execution": requested, "multihop_nodes": nodes})
			if response.Code != http.StatusOK {
				t.Fatalf("SOCKS Update %d: %s", response.Code, response.Body.String())
			}
			updated, err := loadConnectionProfileStore(a)
			if err != nil || len(updated.Profiles) != 1 || updated.Profiles[0].Prefs.MultihopExecution != requested || !reflect.DeepEqual(updated.Profiles[0].NodeChain, saved.NodeChain) {
				t.Fatal("SOCKS Update changed original members or choice", err)
			}
			a.profiles.Profiles[count-2].External.SOCKS5.Password += "-changed"
			before := cloneRouterProfileStore(a.profiles)
			response = postSetup(t, a, "/api/connection-profile/setup/load", map[string]any{"id": saved.ID})
			if response.Code == http.StatusOK || !reflect.DeepEqual(before, a.profiles) || a.cmd != nil {
				t.Fatal("SOCKS saved choice borrowed foreign credentials or partly mutated profiles")
			}
		})
	}
}
