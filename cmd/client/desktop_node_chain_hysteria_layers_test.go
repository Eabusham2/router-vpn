package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"router-vpn/internal/mobilemultihop"
)

// Execute the shipping saved-source compiler and retained preparation. Network
// readiness is exercised separately by the encrypted native provider gate.
func TestDesktopHysteriaExecutionFinalLayers(t *testing.T) {
	for _, target := range []string{"linux", "windows", "darwin"} {
		for _, count := range []int{2, 4, 8} {
			for _, layer := range []string{"aes-256-gcm", "aes-256-gcm+xor-whitening"} {
				for _, choice := range []string{"server", "auto"} {
					t.Run(fmt.Sprintf("%s/%d/%s/%s", target, count, layer, choice), func(t *testing.T) {
						a, launch := desktopHysteriaExecutionLaunchFixture(t, count, target, "", 0, layer)
						if !desktopHysteriaExecutionMembers(launch.chain.selection.Nodes, choice) {
							t.Fatal("paired Hysteria final layer lost product admission")
						}
						e, err := newDesktopNodeChainExecutionSource(launch.chain, choice)
						if err != nil {
							t.Fatal("original layered Hysteria preparation refused", err)
						}
						if err = e.attach(launch); err != nil {
							t.Fatal(err)
						}
						if err = e.bound(launch); err != nil {
							t.Fatal(err)
						}
						original, err := launch.chain.policy.OriginalChain().LaunchInput()
						if err != nil {
							t.Fatal(err)
						}
						var want, got mobilemultihop.NodeChainSource
						if json.Unmarshal([]byte(original), &want) != nil || json.Unmarshal([]byte(e.preparation.LocalSource()), &got) != nil || !reflect.DeepEqual(want, got) {
							t.Fatal("layered Hysteria preparation replaced a captured member")
						}
						proofs := launch.chain.policy.OriginalChain().ProofInventory()
						if len(proofs) != count || proofs[count-1].Mode != "hysteria2" || proofs[count-1].StartLayer != layer {
							t.Fatal("layered Hysteria proof lost final choice")
						}
						for i, proof := range proofs {
							if proof.StartLayer != a.profiles.Profiles[i].StartLayer || proof.NodeID != a.profiles.Profiles[i].NodeProofID {
								t.Fatal("independent paired source replaced", i)
							}
						}
						_, metadata, physical, err := e.readPolicy()
						if err != nil || metadata.TargetOS != target || metadata.Mode != "hysteria2" || physical.SelectedDNS.Detour != mobilemultihop.SelectorTag || physical.SelectedDNS.Physical {
							t.Fatal("layered Hysteria lost selected native policy", err)
						}
						for _, original := range []string{"captured-hysteria-password", "captured-salamander-password", "exit-certificate.example"} {
							if !strings.Contains(string(launch.config), original) {
								t.Fatal("layered Hysteria replaced native authentication")
							}
						}
					})
				}
			}
		}
	}
}

func desktopHysteriaFinalLayerFixture(layer string) desktopImportedExecutionFixture {
	return func(t *testing.T, count int, target, method string, size int, _ ...string) (*app, *desktopNodeLaunch) {
		return desktopHysteriaExecutionLaunchFixture(t, count, target, method, size, layer)
	}
}

// Public parent, Compare selection, retirement and Last execute against the
// existing explicit child/kernel observations. They do not simulate encrypted
// provider receipts or claim installed platform acceptance.
func TestDesktopHysteriaExecutionFinalAES2(t *testing.T) {
	testDesktopHysteriaExecutionPublicConnectWith(t, []int{2}, desktopHysteriaFinalLayerFixture("aes-256-gcm"))
}
func TestDesktopHysteriaExecutionFinalAES8(t *testing.T) {
	testDesktopHysteriaExecutionPublicConnectWith(t, []int{8}, desktopHysteriaFinalLayerFixture("aes-256-gcm"))
}
func TestDesktopHysteriaExecutionFinalXOR2(t *testing.T) {
	testDesktopHysteriaExecutionPublicConnectWith(t, []int{2}, desktopHysteriaFinalLayerFixture("aes-256-gcm+xor-whitening"))
}
func TestDesktopHysteriaExecutionFinalXOR8(t *testing.T) {
	testDesktopHysteriaExecutionPublicConnectWith(t, []int{8}, desktopHysteriaFinalLayerFixture("aes-256-gcm+xor-whitening"))
}
func TestDesktopHysteriaExecutionRestoreFinalAES2(t *testing.T) {
	testDesktopImportedExecutionRestoreWith(t, 2, desktopHysteriaFinalLayerFixture("aes-256-gcm"))
}
func TestDesktopHysteriaExecutionRestoreFinalAES8(t *testing.T) {
	testDesktopImportedExecutionRestoreWith(t, 8, desktopHysteriaFinalLayerFixture("aes-256-gcm"))
}
func TestDesktopHysteriaExecutionRestoreFinalXOR2(t *testing.T) {
	testDesktopImportedExecutionRestoreWith(t, 2, desktopHysteriaFinalLayerFixture("aes-256-gcm+xor-whitening"))
}
func TestDesktopHysteriaExecutionRestoreFinalXOR8(t *testing.T) {
	testDesktopImportedExecutionRestoreWith(t, 8, desktopHysteriaFinalLayerFixture("aes-256-gcm+xor-whitening"))
}

func TestDesktopHysteriaExecutionFinalLayerSourceChange(t *testing.T) {
	for _, layer := range []string{"aes-256-gcm", "aes-256-gcm+xor-whitening"} {
		t.Run(layer, func(t *testing.T) {
			a, original := desktopHysteriaExecutionLaunchFixture(t, 4, "linux", "", 0, layer)
			members := original.chain.selection.Nodes
			// A valid different final policy must produce a different original
			// capture and cannot acquire the first preparation's retained owner.
			e, err := newDesktopNodeChainExecutionSource(original.chain, "server")
			if err != nil {
				t.Fatal(err)
			}
			if err = e.attach(original); err != nil {
				t.Fatal(err)
			}
			selected := a.profiles.Profiles[3]
			selected.StartLayer = "off"
			profiles := append(a.profiles.Profiles[:0:0], a.profiles.Profiles...)
			profiles[3] = selected
			selection, err := resolveDesktopNodeChainSelection(selected, profiles, nodeChainSelectedReferences(members), "local")
			if err != nil {
				t.Fatal(err)
			}
			selection, err = captureNativeNodeChainSelection(context.Background(), clientRoot(a), selection, []string{"hysteria2"}, nil)
			if err != nil {
				t.Fatal(err)
			}
			replacement, err := newDesktopNodeChainLaunch(selection, strings.Repeat("b", 32), "linux")
			if err != nil {
				t.Fatal(err)
			}
			if err = e.bound(replacement); err == nil {
				t.Fatal("changed valid final layer borrowed original execution owner")
			}
			if err = e.bound(original); err != nil {
				t.Fatal("rejected replacement destroyed original execution", err)
			}
		})
	}
}

func TestDesktopHysteriaExecutionFinalLayerStartup(t *testing.T) {
	t.Setenv("HOMEVPN_PORTABLE", "0")
	for _, count := range []int{2, 8} {
		for _, layer := range []string{"aes-256-gcm", "aes-256-gcm+xor-whitening"} {
			t.Run(fmt.Sprintf("%d/%s", count, layer), func(t *testing.T) {
				a, _ := desktopHysteriaExecutionProfiles(t, count, layer)
				// Select the same explicit package-presence boundary as the
				// original Startup source fixtures. No runtime is installed or
				// reported Connected by this source/receipt test.
				manifest := filepath.Join(clientRoot(a), "runtime", "native", "NATIVE-RUNTIME.json")
				if err := os.MkdirAll(filepath.Dir(manifest), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(manifest, []byte("{}\n"), 0600); err != nil {
					t.Fatal(err)
				}
				if !nativeNodeChainPlatformSupported() {
					t.Fatal("layered startup fixture lost its explicit native package boundary")
				}
				profile := a.profiles.Profiles[count-1]
				capture, err := captureStartupNodeChain(a, profile, a.profiles.Profiles, nil)
				if err != nil {
					t.Fatal("layered Hysteria startup lost original source", err)
				}
				last := startupOrderedReceipt(t, &startupPolicyCapture{nodeChain: capture})
				if last.NodeChain.Nodes[count-1].StartLayer != layer || len(last.NodeChain.Nodes[count-1].Sources) != 3 {
					t.Fatal("Hysteria Last omitted original final Start Layer or private source")
				}
				raw, err := json.Marshal(last)
				if err != nil {
					t.Fatal(err)
				}
				var round startupSelection
				if json.Unmarshal(raw, &round) != nil || !reflect.DeepEqual(last, round) {
					t.Fatal("layered Hysteria Last changed its exact canonical receipt")
				}
				if _, err = captureStartupNodeChain(a, profile, a.profiles.Profiles, &round); err != nil {
					t.Fatal("original layered Hysteria Last refused", err)
				}
				for _, fault := range []string{"missing-layer", "invalid-layer", "prefix-layer", "missing-source", "source-order", "changed-layer"} {
					var changed startupSelection
					if err = json.Unmarshal(raw, &changed); err != nil {
						t.Fatal(err)
					}
					final := &changed.NodeChain.Nodes[count-1]
					switch fault {
					case "missing-layer":
						final.StartLayer = ""
					case "invalid-layer":
						final.StartLayer = "xor-only"
					case "prefix-layer":
						changed.NodeChain.Nodes[0].StartLayer = layer
					case "missing-source":
						final.Sources = final.Sources[:2]
					case "source-order":
						final.Sources[1], final.Sources[2] = final.Sources[2], final.Sources[1]
					case "changed-layer":
						final.StartLayer = "aes-256-gcm"
						if layer == "aes-256-gcm" {
							final.StartLayer = "aes-256-gcm+xor-whitening"
						}
					}
					if _, err = captureStartupNodeChain(a, profile, a.profiles.Profiles, &changed); err == nil {
						t.Fatal("Hysteria Last borrowed another final policy or source", fault)
					}
				}
				for _, invalid := range []any{nil, true, 1, "", "off", "AES-256-GCM"} {
					var wire map[string]any
					if json.Unmarshal(raw, &wire) != nil {
						t.Fatal("original Last fixture missing")
					}
					rows := wire["node_chain"].(map[string]any)["nodes"].([]any)
					rows[count-1].(map[string]any)["start_layer"] = invalid
					malformed, _ := json.Marshal(wire)
					var rejected startupSelection
					if json.Unmarshal(malformed, &rejected) == nil {
						t.Fatal("Hysteria Last normalized a malformed final Start Layer", invalid)
					}
				}
			})
		}
	}
}
