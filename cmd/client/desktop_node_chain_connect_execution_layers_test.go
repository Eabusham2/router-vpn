package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"router-vpn/internal/common"
	"router-vpn/internal/mobilemultihop"
)

func desktopCONNECTLayeredApp(t *testing.T, count int, mode, protocol, entry, final string) (*app, []common.MultihopNodeSelection) {
	t.Helper()
	a, nodes := desktopCONNECTPrefixProductApp(t, count-2, mode, protocol)
	a.profiles.Profiles[0].StartLayer = entry
	a.profiles.Profiles[count-1].StartLayer = final
	return a, nodes
}

func desktopCONNECTLayeredLaunch(entry, final, target string) desktopCONNECTExecutionFixture {
	return func(t *testing.T, prefixes int, mode, protocol string) (*app, *desktopNodeLaunch) {
		t.Helper()
		a, nodes := desktopCONNECTLayeredApp(t, prefixes+2, mode, protocol, entry, final)
		selection, err := resolveDesktopNodeChainSelection(a.profiles.Profiles[prefixes+1], a.profiles.Profiles, nodes, "local")
		if err != nil {
			t.Fatal(err)
		}
		selection, err = captureNativeNodeChainSelection(context.Background(), clientRoot(a), selection, []string{"shadowsocks"}, nil)
		if err != nil {
			t.Fatal("original layered CONNECT capture refused", err)
		}
		launch, err := newDesktopNodeChainLaunch(selection, strings.Repeat("a", 32), target)
		if err != nil {
			t.Fatal(err)
		}
		return a, launch
	}
}

func assertDesktopCONNECTLayers(t *testing.T, raw, entry, final string, count int) {
	t.Helper()
	var source mobilemultihop.NodeChainSource
	if json.Unmarshal([]byte(raw), &source) != nil || source.Schema != 4 || len(source.Nodes) != count || len(source.IdentitySources) != count || source.IdentitySources[count-2] != "" {
		t.Fatal("layered CONNECT changed its complete original source")
	}
	for position, layer := range map[int]string{0: entry, count - 1: final} {
		var member struct {
			Profile string `json:"profile_json"`
		}
		var profile struct {
			Layer string `json:"start_layer"`
		}
		if json.Unmarshal([]byte(source.Nodes[position]), &member) != nil || json.Unmarshal([]byte(member.Profile), &profile) != nil || profile.Layer != layer {
			t.Fatal("layered CONNECT replaced an independent original layer", position)
		}
	}
}

func TestDesktopCONNECTExecutionCapturedFinalLayers(t *testing.T) {
	layers := []string{"off", "aes-256-gcm", "aes-256-gcm+xor-whitening"}
	for i, entry := range layers {
		for j, final := range layers {
			t.Run(entry+"/"+final, func(t *testing.T) {
				for _, protocol := range []string{"http-connect", "https-connect"} {
					a, launch := desktopCONNECTLayeredLaunch(entry, final, []string{"linux", "windows", "darwin"}[j])(t, 1, []string{"wg", "awg2-fast", "awg2-strong"}[i], protocol)
					for _, requested := range []string{"server", "auto"} {
						if !desktopCONNECTTrioExecutionMembers(launch.chain.selection.Nodes, requested) {
							t.Fatal("original layered CONNECT execution refused")
						}
						execution, err := newDesktopNodeChainExecutionSource(launch.chain, requested)
						if err != nil {
							t.Fatal("original layered CONNECT execution refused", err)
						}
						assertDesktopCONNECTLayers(t, execution.preparation.LocalSource(), entry, final, 3)
						if _, _, _, err = execution.readPolicy(); err != nil {
							t.Fatal(err)
						}
						if execution.connectPhysical == nil || execution.socksPhysical != nil || execution.physical != nil {
							t.Fatal("CONNECT borrowed a different physical owner")
						}
						for _, bad := range []string{"AES-256-GCM", "xor-only", "foreign"} {
							changed := cloneDesktopNodeChainMembers(launch.chain.selection.Nodes)
							changed[2].Profile.StartLayer = bad
							if desktopCONNECTTrioExecutionMembers(changed, requested) {
								t.Fatal("CONNECT admitted an invalid final layer")
							}
						}
					}
					before := cloneRouterProfileStore(a.profiles)
					a.profiles.Profiles[2].StartLayer = "foreign"
					if launch.chain.selection.Native.chain.currentContext(context.Background(), a) == nil {
						t.Fatal("old CONNECT capture accepted a replacement final policy")
					}
					a.profiles = before
				}
			})
		}
	}
}

func TestDesktopCONNECTExecutionLayeredSavedProfiles(t *testing.T) {
	for _, count := range []int{4, 8} {
		for _, final := range []string{"aes-256-gcm", "aes-256-gcm+xor-whitening"} {
			t.Run(fmt.Sprint(count)+"/"+final, func(t *testing.T) {
				entry := "aes-256-gcm+xor-whitening"
				if final == entry {
					entry = "aes-256-gcm"
				}
				if count == 8 {
					entry = "off"
				}
				for _, protocol := range []string{"http-connect", "https-connect"} {
					for _, requested := range []string{"server", "auto"} {
						a, nodes := desktopCONNECTLayeredApp(t, count, "awg2-strong", protocol, entry, final)
						save := map[string]any{"name": "Independent CONNECT layers", "mode": "shadowsocks", "multihop_enabled": true, "multihop_execution": requested, "multihop_nodes": nodes}
						response := postSetup(t, a, "/api/connection-profile/setup/save", save)
						if response.Code != http.StatusOK {
							t.Fatalf("layered CONNECT Save %d: %s", response.Code, response.Body.String())
						}
						store, err := loadConnectionProfileStore(a)
						if err != nil || len(store.Profiles) != 1 {
							t.Fatal("layered CONNECT saved source absent", err)
						}
						original := store.Profiles[0]
						if len(original.NodeChain) != count || original.NodeChain[0].Preferences.StartLayer != entry || original.NodeChain[count-1].Preferences.StartLayer != final || original.NodeChain[count-2].External == nil || original.Prefs.MultihopExecution != requested {
							t.Fatal("layered CONNECT Save replaced its captured policy")
						}
						response = postSetup(t, a, "/api/connection-profile/setup/load", map[string]any{"id": original.ID})
						if response.Code != http.StatusOK {
							t.Fatalf("layered CONNECT Load %d: %s", response.Code, response.Body.String())
						}
						save["id"], save["name"] = original.ID, "Updated CONNECT layers"
						response = postSetup(t, a, "/api/connection-profile/setup/update", save)
						if response.Code != http.StatusOK {
							t.Fatalf("layered CONNECT Update %d: %s", response.Code, response.Body.String())
						}
						next, err := loadConnectionProfileStore(a)
						if err != nil || len(next.Profiles) != 1 || !reflect.DeepEqual(next.Profiles[0].NodeChain, original.NodeChain) || a.cmd != nil || a.state.Connected {
							t.Fatal("layered CONNECT profile changed source or fabricated a connection", err)
						}
						proxy := a.profiles.Profiles[count-2].External.HTTPConnect
						if protocol == "https-connect" {
							proxy = a.profiles.Profiles[count-2].External.HTTPSConnect
						}
						proxy.Password += "-foreign"
						before := cloneRouterProfileStore(a.profiles)
						response = postSetup(t, a, "/api/connection-profile/setup/load", map[string]any{"id": original.ID})
						if response.Code == http.StatusOK || !reflect.DeepEqual(before, a.profiles) || a.cmd != nil {
							t.Fatal("layered CONNECT Load accepted changed original credentials")
						}
						response = postSetup(t, a, "/api/connection-profile/setup/delete", map[string]any{"id": original.ID})
						if response.Code != http.StatusOK {
							t.Fatalf("layered CONNECT Delete %d: %s", response.Code, response.Body.String())
						}
					}
				}
			})
		}
	}
}

func TestDesktopCONNECTExecutionLayeredPublicServer(t *testing.T) {
	testDesktopCONNECTExecutionPublicConnectFixture(t, 4, desktopCONNECTLayeredLaunch("aes-256-gcm+xor-whitening", "aes-256-gcm", "windows"), desktopCONNECTExecutionChoice{"server", "server"})
}
func TestDesktopCONNECTExecutionLayeredPublicCompareLocal(t *testing.T) {
	testDesktopCONNECTExecutionPublicConnectFixture(t, 4, desktopCONNECTLayeredLaunch("aes-256-gcm", "aes-256-gcm+xor-whitening", "windows"), desktopCONNECTExecutionChoice{"auto", "local"})
}
func TestDesktopCONNECTExecutionLayeredPublicCompareServer(t *testing.T) {
	testDesktopCONNECTExecutionPublicConnectFixture(t, 8, desktopCONNECTLayeredLaunch("off", "aes-256-gcm+xor-whitening", "windows"), desktopCONNECTExecutionChoice{"auto", "server"})
}
func TestDesktopCONNECTExecutionLayeredLast(t *testing.T) {
	for _, count := range []int{4, 8} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			entry, final := "aes-256-gcm+xor-whitening", "aes-256-gcm"
			if count == 8 {
				entry, final = "off", "aes-256-gcm+xor-whitening"
			}
			testDesktopCONNECTExecutionRestoreRetainsChosenSource(t, func(t *testing.T) (*app, *desktopNodeLaunch) {
				return desktopCONNECTLayeredLaunch(entry, final, "windows")(t, count-2, "awg2-strong", "https-connect")
			})
		})
	}
}
