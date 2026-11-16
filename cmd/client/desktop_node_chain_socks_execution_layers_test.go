package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"router-vpn/internal/common"
	"router-vpn/internal/mobilemultihop"
)

func desktopSOCKSExecutionLayerProfiles(t *testing.T, mode, entry, final string) (*app, []common.MultihopNodeSelection) {
	t.Helper()
	a, nodes := desktopSOCKSCaptureFixture(t, mode, "password", "off")
	// Set independent saved policy before any source or native capture.
	a.profiles.Profiles[0].StartLayer = entry
	a.profiles.Profiles[2].StartLayer = final
	return a, nodes
}

func desktopSOCKSExecutionLayerFixture(entry, final string) func(*testing.T, string, string) (*app, multihopSelection, *desktopNodeLaunch) {
	return desktopSOCKSExecutionLayerPrefixFixture(3, entry, final)
}
func desktopSOCKSExecutionLayerPrefixFixture(count int, entry, final string) func(*testing.T, string, string) (*app, multihopSelection, *desktopNodeLaunch) {
	return func(t *testing.T, mode, target string) (*app, multihopSelection, *desktopNodeLaunch) {
		t.Helper()
		a, nodes := desktopSOCKSPrefixCaptureFixture(t, count-2, mode, "password", "off")
		a.profiles.Profiles[0].StartLayer = entry
		a.profiles.Profiles[count-1].StartLayer = final
		selection, err := resolveDesktopNodeChainSelection(a.profiles.Profiles[count-1], a.profiles.Profiles, nodes, "local")
		if err != nil {
			t.Fatal(err)
		}
		selection, err = captureNativeNodeChainSelection(context.Background(), clientRoot(a), selection, []string{"shadowsocks"}, nil)
		if err != nil {
			t.Fatal("original independently layered SOCKS capture", err)
		}
		launch, err := newDesktopNodeChainLaunch(selection, strings.Repeat("b", 32), target)
		if err != nil {
			t.Fatal(err)
		}
		return a, selection, launch
	}
}

func assertDesktopSOCKSExecutionLayers(t *testing.T, raw, entry, final string) {
	assertDesktopSOCKSExecutionLayersCount(t, raw, entry, final, 3)
}
func assertDesktopSOCKSExecutionLayersCount(t *testing.T, raw, entry, final string, count int) {
	t.Helper()
	var source mobilemultihop.NodeChainSource
	if json.Unmarshal([]byte(raw), &source) != nil || source.Schema != 3 || len(source.Nodes) != count || len(source.IdentitySources) != count || source.IdentitySources[count-2] != "" {
		t.Fatal("layered SOCKS preparation changed its original typed trio")
	}
	for position, expected := range map[int]string{0: entry, count - 1: final} {
		var input struct {
			Profile string `json:"profile_json"`
		}
		var profile struct {
			Layer string `json:"start_layer"`
		}
		if json.Unmarshal([]byte(source.Nodes[position]), &input) != nil || json.Unmarshal([]byte(input.Profile), &profile) != nil || profile.Layer != expected {
			t.Fatal("SOCKS execution replaced an independently captured layer", position)
		}
	}
}

func TestDesktopSOCKSExecutionCapturedFinalLayers(t *testing.T) {
	layers := []string{"off", "aes-256-gcm", "aes-256-gcm+xor-whitening"}
	for i, entry := range layers {
		for j, final := range layers {
			t.Run(entry+"/"+final, func(t *testing.T) {
				mode := []string{"wg", "awg2-fast", "awg2-strong"}[i]
				target := []string{"linux", "windows", "darwin"}[j]
				a, selection, launch := desktopSOCKSExecutionLayerFixture(entry, final)(t, mode, target)
				for _, requested := range []string{"server", "auto"} {
					if !desktopSOCKSTrioExecutionMembers(selection.Nodes, requested) {
						t.Fatal("original layered SOCKS execution refused")
					}
					execution, err := newDesktopNodeChainExecutionSource(launch.chain, requested)
					if err != nil {
						t.Fatal("original layered SOCKS execution refused", err)
					}
					assertDesktopSOCKSExecutionLayers(t, execution.preparation.LocalSource(), entry, final)
					if _, _, _, err = execution.readPolicy(); err != nil {
						t.Fatal(err)
					}
					if execution.socksPhysical == nil || execution.physical != nil || execution.connectPhysical != nil {
						t.Fatal("layered SOCKS borrowed another physical owner")
					}
					for _, bad := range []string{"AES-256-GCM", "xor-whitening", "foreign"} {
						changed := cloneDesktopNodeChainMembers(selection.Nodes)
						changed[2].Profile.StartLayer = bad
						if desktopSOCKSTrioExecutionMembers(changed, requested) {
							t.Fatal("SOCKS execution admitted malformed final layer")
						}
					}
				}
				before := cloneRouterProfileStore(a.profiles)
				a.profiles.Profiles[2].StartLayer = "foreign"
				if selection.Native.chain.currentContext(context.Background(), a) == nil {
					t.Fatal("layered SOCKS source accepted changed final policy")
				}
				a.profiles = before
			})
		}
	}
}

func TestDesktopSOCKSExecutionLayeredSavedProfiles(t *testing.T) {
	for _, final := range []string{"aes-256-gcm", "aes-256-gcm+xor-whitening"} {
		for _, requested := range []string{"server", "auto"} {
			t.Run(final+"/"+requested, func(t *testing.T) {
				entry := "aes-256-gcm+xor-whitening"
				if final == entry {
					entry = "aes-256-gcm"
				}
				a, nodes := desktopSOCKSExecutionLayerProfiles(t, "wg", entry, final)
				save := map[string]any{"name": "Independent SOCKS layers", "mode": "shadowsocks", "multihop_enabled": true, "multihop_execution": requested, "multihop_nodes": nodes}
				response := postSetup(t, a, "/api/connection-profile/setup/save", save)
				if response.Code != http.StatusOK {
					t.Fatalf("layered SOCKS Save %d: %s", response.Code, response.Body.String())
				}
				store, err := loadConnectionProfileStore(a)
				if err != nil || len(store.Profiles) != 1 {
					t.Fatal("layered saved source absent", err)
				}
				original := store.Profiles[0]
				if original.NodeChain[0].Preferences.StartLayer != entry || original.NodeChain[2].Preferences.StartLayer != final || original.NodeChain[1].External == nil || original.Prefs.MultihopExecution != requested {
					t.Fatal("Save replaced captured layer or execution")
				}
				response = postSetup(t, a, "/api/connection-profile/setup/load", map[string]any{"id": original.ID})
				if response.Code != http.StatusOK {
					t.Fatalf("layered SOCKS Load %d: %s", response.Code, response.Body.String())
				}
				save["id"] = original.ID
				save["name"] = "Updated independent SOCKS layers"
				response = postSetup(t, a, "/api/connection-profile/setup/update", save)
				if response.Code != http.StatusOK {
					t.Fatalf("layered SOCKS Update %d: %s", response.Code, response.Body.String())
				}
				next, err := loadConnectionProfileStore(a)
				if err != nil || len(next.Profiles) != 1 || !reflect.DeepEqual(next.Profiles[0].NodeChain, original.NodeChain) || a.cmd != nil || a.state.Connected {
					t.Fatal("layered roundtrip changed source or fabricated connection", err)
				}
				a.profiles.Profiles[1].External.SOCKS5.Password += "-foreign"
				before := cloneRouterProfileStore(a.profiles)
				response = postSetup(t, a, "/api/connection-profile/setup/load", map[string]any{"id": original.ID})
				if response.Code == http.StatusOK || !reflect.DeepEqual(before, a.profiles) || a.cmd != nil {
					t.Fatal("layered Load accepted substituted credentials")
				}
			})
		}
	}
}

func testDesktopSOCKSExecutionLayeredPublic(t *testing.T, requested, winner string) {
	for _, final := range []string{"aes-256-gcm", "aes-256-gcm+xor-whitening"} {
		t.Run(final, func(t *testing.T) {
			entry := "aes-256-gcm+xor-whitening"
			if entry == final {
				entry = "aes-256-gcm"
			}
			testDesktopSOCKSExecutionPublicFixture(t, requested, winner, desktopSOCKSExecutionLayerFixture(entry, final))
		})
	}
}
func TestDesktopSOCKSExecutionLayeredPublicServer(t *testing.T) {
	testDesktopSOCKSExecutionLayeredPublic(t, "server", "server")
}
func TestDesktopSOCKSExecutionLayeredPublicCompareLocal(t *testing.T) {
	testDesktopSOCKSExecutionLayeredPublic(t, "auto", "local")
}
func TestDesktopSOCKSExecutionLayeredPublicCompareServer(t *testing.T) {
	testDesktopSOCKSExecutionLayeredPublic(t, "auto", "server")
}

func TestDesktopSOCKSExecutionLayeredLast(t *testing.T) {
	testDesktopSOCKSExecutionLayeredLastCount(t, 3)
}
func TestDesktopSOCKSExecutionLayeredPrefixLast(t *testing.T) {
	testDesktopSOCKSExecutionLayeredLastCount(t, 8)
}
func testDesktopSOCKSExecutionLayeredLastCount(t *testing.T, count int) {
	for _, winner := range []string{"local", "server"} {
		t.Run(winner, func(t *testing.T) {
			entry, final := "aes-256-gcm", "aes-256-gcm+xor-whitening"
			if winner == "local" {
				entry, final = final, entry
			}
			f, session := prepareDesktopSOCKSExecutionModelFixture(t, "auto", winner, desktopSOCKSExecutionLayerPrefixFixture(count, entry, final))
			if err := session.startContext(f.operation); err != nil {
				t.Fatal(err)
			}
			restore, err := session.CaptureRestore(f.operation)
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err = restore.newLaunchContext(f.operation, strings.Repeat("b", 32), "windows"); err == nil {
				t.Fatal("unjoined layered SOCKS owner restored")
			}
			held := errors.New("original layered SOCKS child still joining")
			f.processes[0].closeErr = held
			if err = restore.retireContext(context.Background()); !errors.Is(err, held) || session.launch.ownedNode.retired {
				t.Fatal("failed layered join released original owner", err)
			}
			f.processes[0].closeErr = nil
			if err = restore.retireContext(context.Background()); err != nil {
				t.Fatal(err)
			}
			<-f.pulseDone
			next, execution, err := restore.newLaunchContext(f.operation, strings.Repeat("b", 32), "windows")
			if err != nil {
				t.Fatal(err)
			}
			last, present, err := execution.preparation.SOCKSDesktopLast()
			if err != nil || !present || last.Execution() != winner || last.Target() != mobilemultihop.Targets[1] || f.starts != 1 {
				t.Fatal("layered Last reran Compare or replaced winner", err)
			}
			assertDesktopSOCKSExecutionLayersCount(t, execution.preparation.LocalSource(), entry, final, count)
			_, meta, _, err := next.chain.socksPolicy.PhysicalReadValidated()
			if err != nil || execution.preparation.LocalSource() != session.execution.preparation.LocalSource() || next.chain.selection.Native != session.selection.Native || meta.RestoredMTU != f.live.MTU || execution.socksPhysical == nil || execution.connectPhysical != nil || execution.physical != nil {
				t.Fatal("layered Last lost original source or readback", err)
			}
		})
	}
}

func TestDesktopSOCKSExecutionLayeredPrefixes(t *testing.T) {
	for _, count := range []int{4, 8} {
		for _, final := range []string{"aes-256-gcm", "aes-256-gcm+xor-whitening"} {
			t.Run(fmt.Sprint(count)+"/"+final, func(t *testing.T) {
				for _, requested := range []string{"server", "auto"} {
					a, selection, launch := desktopSOCKSExecutionLayerPrefixFixture(count, "aes-256-gcm", final)(t, "wg", "windows")
					execution, err := newDesktopNodeChainExecutionSource(launch.chain, requested)
					if err != nil {
						t.Fatal("original layered SOCKS prefix refused", err)
					}
					var source mobilemultihop.NodeChainSource
					if json.Unmarshal([]byte(execution.preparation.LocalSource()), &source) != nil || len(source.Nodes) != count || source.Schema != 3 || source.IdentitySources[count-2] != "" {
						t.Fatal("layered prefix lost original positions")
					}
					original, err := launch.chain.socksPolicy.NativeSource()
					if err != nil {
						t.Fatal(err)
					}
					raw, err := original.Source()
					if err != nil || raw != execution.preparation.LocalSource() {
						t.Fatal("layered prefix replaced original source", err)
					}
					if _, _, _, err = execution.readPolicy(); err != nil {
						t.Fatal(err)
					}
					response := postSetup(t, a, "/api/connection-profile/setup/save", map[string]any{"name": "Layered prefix " + requested, "mode": "shadowsocks", "multihop_enabled": true, "multihop_execution": requested, "multihop_nodes": nodeChainSelectedReferences(selection.Nodes)})
					if response.Code != http.StatusOK {
						t.Fatalf("layered prefix Save %d: %s", response.Code, response.Body.String())
					}
					store, err := loadConnectionProfileStore(a)
					if err != nil || len(store.Profiles) == 0 {
						t.Fatal("layered prefix store", err)
					}
					var saved connectionProfileRecord
					matches := 0
					for _, record := range store.Profiles {
						if record.Name == "Layered prefix "+requested {
							saved = record
							matches++
						}
					}
					if matches != 1 || saved.Prefs.MultihopExecution != requested {
						t.Fatal("layered prefix Save lost its exact requested record")
					}
					if len(saved.NodeChain) != count || saved.NodeChain[count-1].Preferences.StartLayer != final || saved.NodeChain[0].Preferences.StartLayer != "aes-256-gcm" {
						t.Fatal("layered prefix Save replaced policy")
					}
					response = postSetup(t, a, "/api/connection-profile/setup/load", map[string]any{"id": saved.ID})
					if response.Code != http.StatusOK {
						t.Fatalf("layered prefix Load %d: %s", response.Code, response.Body.String())
					}
				}
			})
		}
	}
}
func TestDesktopSOCKSExecutionLayeredPrefixPublic4Server(t *testing.T) {
	testDesktopSOCKSExecutionPublicFixture(t, "server", "server", desktopSOCKSExecutionLayerPrefixFixture(4, "aes-256-gcm+xor-whitening", "aes-256-gcm"))
}
func TestDesktopSOCKSExecutionLayeredPrefixPublic8CompareServer(t *testing.T) {
	testDesktopSOCKSExecutionPublicFixture(t, "auto", "server", desktopSOCKSExecutionLayerPrefixFixture(8, "aes-256-gcm", "aes-256-gcm+xor-whitening"))
}
