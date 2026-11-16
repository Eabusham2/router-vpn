package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"testing"

	"router-vpn/internal/common"
)

func TestDesktopOpenVPNExecutionSavedProfileKeepsCompleteSource(t *testing.T) {
	for _, count := range []int{3, 4, 8} {
		t.Run(fmt.Sprint(count), func(t *testing.T) { testDesktopOpenVPNExecutionSavedProfile(t, count) })
	}
}
func testDesktopOpenVPNExecutionSavedProfile(t *testing.T, count int) {
	for _, requested := range []string{"server", "auto"} {
		t.Run(requested, func(t *testing.T) {
			a, nodes, _, _ := desktopOpenVPNExecutionProfiles(t, count, "wg", "tcp", "off")
			response := postSetup(t, a, "/api/connection-profile/setup/save", map[string]any{"name": "Original OpenVPN execution", "mode": "shadowsocks", "multihop_enabled": true, "multihop_execution": requested, "multihop_nodes": nodes})
			if response.Code != http.StatusOK {
				t.Fatalf("OpenVPN Save %d: %s", response.Code, response.Body.String())
			}
			store, err := loadConnectionProfileStore(a)
			if err != nil || len(store.Profiles) != 1 {
				t.Fatal("OpenVPN saved source absent", err)
			}
			saved := store.Profiles[0]
			if saved.Prefs.MultihopExecution != requested || len(saved.NodeChain) != count || saved.NodeChain[count-2].NodeProofID != "" || saved.NodeChain[count-2].External == nil || saved.NodeChain[count-2].External.Protocol != "openvpn" {
				t.Fatal("OpenVPN Save changed original source family")
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
					changed.NodeChain[count-1].Preferences.StartLayer = "AES-256-GCM"
				case "middle-kind":
					changed.NodeChain[count-2].NodeKind = "router-vpn"
				case "middle-protocol":
					changed.NodeChain[count-2].External.Protocol = "http-connect"
				case "source-digest":
					changed.NodeChain[count-2].Sources[0].SHA256 = "foreign"
				}
				if validateSavedNodeChain(changed) == nil {
					t.Fatal("saved OpenVPN execution admitted changed source", fault)
				}
			}
			response = postSetup(t, a, "/api/connection-profile/setup/load", map[string]any{"id": saved.ID})
			if response.Code != http.StatusOK {
				t.Fatalf("OpenVPN Load %d: %s", response.Code, response.Body.String())
			}
			var body map[string]any
			if json.Unmarshal(response.Body.Bytes(), &body) != nil || body["multihop_execution"] != requested || a.cmd != nil || a.state.Connected {
				t.Fatal("OpenVPN Load changed choice or fabricated connection")
			}
			final, _ := profileByID(a.profiles.Profiles, a.profiles.SelectedID)
			if !reflect.DeepEqual(final.MultihopNodes, nodes) || final.MultihopExecution != requested {
				t.Fatal("OpenVPN Load lost original ordered members")
			}
			response = postSetup(t, a, "/api/connection-profile/setup/update", map[string]any{"id": saved.ID, "name": "Updated OpenVPN choice", "mode": "shadowsocks", "multihop_enabled": true, "multihop_execution": requested, "multihop_nodes": nodes})
			if response.Code != http.StatusOK {
				t.Fatalf("OpenVPN Update %d: %s", response.Code, response.Body.String())
			}
			updated, err := loadConnectionProfileStore(a)
			if err != nil || len(updated.Profiles) != 1 || updated.Profiles[0].Prefs.MultihopExecution != requested || !reflect.DeepEqual(updated.Profiles[0].NodeChain, saved.NodeChain) {
				t.Fatal("OpenVPN Update changed original members or choice", err)
			}
			a.profiles.Profiles[count-2].External.OpenVPN.Password += "-changed"
			before := cloneRouterProfileStore(a.profiles)
			response = postSetup(t, a, "/api/connection-profile/setup/load", map[string]any{"id": saved.ID})
			if response.Code == http.StatusOK || !reflect.DeepEqual(before, a.profiles) || a.cmd != nil {
				t.Fatal("OpenVPN saved choice borrowed foreign credentials or partly mutated profiles")
			}
		})
	}
}
