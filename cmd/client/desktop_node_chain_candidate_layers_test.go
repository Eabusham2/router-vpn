package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"router-vpn/internal/mobilemultihop"
)

func TestDesktopCandidatePairedLayersCaptureOriginalClosure(t *testing.T) {
	for _, target := range []string{"linux", "windows", "darwin"} {
		for _, layer := range []string{"off", "aes-256-gcm", "aes-256-gcm+xor-whitening"} {
			t.Run(target+"/"+layer, func(t *testing.T) {
				a, nodes := desktopNodeChainCaptureFixture(t, 4)
				for i := range a.profiles.Profiles {
					a.profiles.Profiles[i].KillSwitch = true
					a.profiles.Profiles[i].KillSwitchPolicy = "on-connect"
				}
				a.profiles.Profiles[3].StartLayer = layer
				a.profiles.Profiles[3].MultihopExecution = "local"
				control := a.profiles.Profiles[3]
				selection, err := resolveDesktopNodeChainSelection(control, a.profiles.Profiles, nodes, "local")
				if err != nil {
					t.Fatal(err)
				}
				selection, err = captureNativeMultihopSelection(context.Background(), clientRoot(a), selection, []string{"shadowsocks"}, nil)
				if err != nil {
					t.Fatal(err)
				}
				launch, err := newDesktopNodeChainLaunch(selection, strings.Repeat("a", 32), target)
				if err != nil {
					t.Fatal(err)
				}
				catalog, err := captureDesktopNodeChainCandidateSources(context.Background(), a, launch, 2, []string{control.ID})
				if err != nil {
					t.Fatal("original paired layered candidate omitted from catalog", err)
				}
				var inventory mobilemultihop.NodeChainCandidateInventory
				if json.Unmarshal([]byte(catalog.inventory), &inventory) != nil || len(inventory.Inputs) != 1 {
					t.Fatal("original candidate inventory")
				}
				member, err := mobilemultihop.ParseNodeLaunchInput(inventory.Inputs[0])
				if err != nil {
					t.Fatal(err)
				}
				var graph map[string]any
				if json.Unmarshal([]byte(member.Config()), &graph) != nil {
					t.Fatal("concrete original closure")
				}
				tag := graph["route"].(map[string]any)["final"]
				var final map[string]any
				for _, raw := range graph["outbounds"].([]any) {
					row := raw.(map[string]any)
					if row["tag"] == tag {
						final = row
					}
				}
				expected := "shadowsocks"
				if layer == "aes-256-gcm+xor-whitening" {
					expected = "routervpn-aes-xor"
				}
				path := filepath.Join(clientRoot(a), "generated", control.ID, "shadowsocks", "sing-box.json")
				original, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				var source map[string]any
				if json.Unmarshal(original, &source) != nil {
					t.Fatal("original source")
				}
				originalSS := source["outbounds"].([]any)[0].(map[string]any)
				port := originalSS["server_port"]
				if expected == "routervpn-aes-xor" {
					port = float64(8389)
				}
				if final == nil || final["type"] != expected || final["password"] != originalSS["password"] || final["server"] != originalSS["server"] || final["server_port"] != port || final["detour"] != nil || final["udp_over_tcp"] != nil {
					t.Fatal("desktop candidate changed captured concrete owner or TCP endpoint")
				}
				if !strings.Contains(catalog.plan.Metadata(), member.SourceSHA256()) || strings.Contains(catalog.plan.Metadata(), originalSS["password"].(string)) {
					t.Fatal("catalog lost source identity or exposed a key")
				}
				before := cloneRouterProfileStore(a.profiles)
				next, refs, err := orderedCandidateProposal(selection.Nodes, 2, control, a.profiles.Profiles)
				if err != nil || !reflect.DeepEqual(refs, nodes) || next.StartLayer != layer || next.MultihopExecution != control.MultihopExecution {
					t.Fatal("paired proposal lost complete source policy", err)
				}
				proposal, err := captureOrderedCandidateProposal(context.Background(), clientRoot(a), next, a.profiles.Profiles, refs)
				if err != nil || proposal.validate(context.Background(), next, a.profiles.Profiles) != nil || !reflect.DeepEqual(before, a.profiles) {
					t.Fatal("paired layered proposal bypassed complete compiler or changed live profiles", err)
				}
				originalSS["password"] = "eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHg="
				changed, _ := json.Marshal(source)
				if err := os.WriteFile(path, changed, 0600); err != nil {
					t.Fatal(err)
				}
				if proposal.validate(context.Background(), next, a.profiles.Profiles) == nil {
					t.Fatal("changed captured key retained proposal authority")
				}
			})
		}
	}
}

func TestDesktopCandidatePairedLayersKeepImportedBoundary(t *testing.T) {
	for _, layer := range []string{"aes-256-gcm", "aes-256-gcm+xor-whitening", "xor-whitening", "foreign"} {
		t.Run(layer, func(t *testing.T) {
			a, launch := desktopNodeChainLaunchFixture(t, 3, "linux")
			id := desktopCandidateAddCustomSource(t, a, "2022-blake3-aes-256-gcm")
			a.profiles.Profiles[len(a.profiles.Profiles)-1].StartLayer = layer
			if _, err := captureDesktopNodeChainCandidateSources(context.Background(), a, launch, 0, []string{id}); err == nil {
				t.Fatal("imported source acquired paired Start Layer authority")
			}
		})
	}
}
