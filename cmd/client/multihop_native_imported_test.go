package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"router-vpn/internal/common"
	"router-vpn/internal/mobilemultihop"
)

func desktopImportedFixture(t *testing.T, protocol, finalMode string) (string, multihopSelection) {
	t.Helper()
	root, paired := nativeMultihopCapturedFixture(t, "wg", "off")
	entry, _ := desktopExternalNativeFixture(t, protocol)
	entry.ID, entry.Name = "imported-entry", "Independent imported entry"
	entry.DNSMode, entry.DNSProtocol, entry.DNSHost, entry.DNSPort = "home", "", "", 0
	if protocol == "shadowsocks" {
		entry.External.Shadowsocks.Method = "2022-blake3-aes-256-gcm"
		entry.External.Shadowsocks.Password = base64.StdEncoding.EncodeToString([]byte(strings.Repeat("e", 32)))
	}
	if protocol == "wireguard" {
		entry.External.WireGuard.MTU = 1500
	}
	if protocol == "amneziawg" {
		entry.External.AmneziaWG.MTU = 1500
	}
	paired.Exit.DAITAEnabled = false
	paired.Exit.MultihopEnabled, paired.Exit.MultihopEntryID, paired.Exit.MultihopExitID = true, entry.ID, paired.Exit.ID
	paired.Exit.MultihopEntryMode, paired.Exit.MultihopExecution = protocol, "local"
	if protocol == "http-connect" || protocol == "https-connect" {
		paired.Exit.DNSMode, paired.Exit.DNSProtocol, paired.Exit.DNSHost, paired.Exit.DNSPort = "custom", "tcp", "203.0.113.53", 5353
	}
	return root, multihopSelection{Control: paired.Exit, Entry: entry, Exit: paired.Exit, Base: "native", EntryMode: protocol, ExitMode: finalMode}
}

func TestDesktopImportedNativeCaptureExactGraphAndPhysicalSockets(t *testing.T) {
	for _, protocol := range []string{"shadowsocks", "hysteria2", "socks5", "http-connect", "https-connect"} {
		modes := []string{"shadowsocks", "reality-vision"}
		if protocol == "shadowsocks" || protocol == "hysteria2" {
			modes = append(modes, "hysteria2", "wg", "awg2-fast", "awg2-strong")
		}
		for _, finalMode := range modes {
			t.Run(protocol+"/"+finalMode, func(t *testing.T) {
				root, selected := desktopImportedFixture(t, protocol, finalMode)
				before, _ := json.Marshal(selected)
				sel, err := captureNativeMultihopSelection(context.Background(), root, selected, []string{finalMode}, nil)
				if protocol == "socks5" && finalMode == "shadowsocks" {
					if !errors.Is(err, mobilemultihop.ErrDynamicPhysicalEgress) {
						t.Fatal("unowned negotiated SOCKS relay was admitted", err)
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				after, _ := json.Marshal(selected)
				if string(before) != string(after) || !sel.Native.imported || sel.Native.validate(sel) != nil {
					t.Fatal("capture changed an original profile")
				}
				launch, err := compileRetainedNativeMultihopLaunch(sel, nil)
				if err != nil {
					t.Fatal(err)
				}
				graph := retainedGraph(t, launch.config)
				emitDesktopImportedFixture(t, protocol+"--"+finalMode+".json", launch.config)
				if len(graph["inbounds"].([]any)) != 3 || strings.Contains(string(launch.config), "entry-private") || launch.profileID != sel.Exit.ID || launch.policyProfileID != sel.Exit.ID || launch.endpoint != sel.Entry.Endpoint {
					t.Fatal("entry acquired paired credentials or lost final policy ownership")
				}
				rules := graph["route"].(map[string]any)["rules"].([]any)
				if rules[0].(map[string]any)["outbound"] != "entry-wg" || rules[1].(map[string]any)["outbound"] != "proxy" {
					t.Fatal("entry and final proofs did not retain their own lanes")
				}
				for _, tuple := range launch.nodePhysicalEgress {
					if tuple.Host != sel.Entry.Endpoint || tuple.Host == sel.Exit.Endpoint {
						t.Fatal("inner paired final gained a direct physical exception", tuple)
					}
				}
				if !strings.Contains(string(launch.config), sel.Exit.AdGuardIPv4) && sel.Exit.DNSMode == "home" {
					t.Fatal("paired final lost its default Home AdGuard DNS")
				}
				dns := graph["dns"].(map[string]any)
				servers := dns["servers"].([]any)
				if len(servers) != 1 || servers[0].(map[string]any)["detour"] != "proxy" || servers[0].(map[string]any)["server"] != sel.Exit.AdGuardIPv4 && sel.Exit.DNSMode == "home" || strings.Contains(string(mustImportedJSON(t, dns)), "1.1.1.1") {
					t.Fatal("temporary rescue seed leaked into the final-owned DNS graph", dns)
				}
				if binary := os.Getenv("ROUTERVPN_VIA_ENTRY_NATIVE_CLI"); binary != "" {
					path := filepath.Join(t.TempDir(), "sing-box.json")
					if err := os.WriteFile(path, launch.config, 0600); err != nil {
						t.Fatal(err)
					}
					if output, err := exec.Command(binary, "check", "-c", path).CombinedOutput(); err != nil {
						t.Fatalf("native graph check: %v: %s", err, output)
					}
				}
				_, server := executionFixture()
				if _, err := compileRetainedNativeMultihopLaunch(sel, &server); err == nil {
					t.Fatal("imported public proof acquired private Server authority")
				}
				restored := sel
				restored.restoreMTU = 1280
				other, err := compileRetainedNativeMultihopLaunch(restored, nil)
				if err != nil || !reflect.DeepEqual(other.nodePhysicalEgress, launch.nodePhysicalEgress) {
					t.Fatal("restoration substituted the original physical graph", err)
				}
				if string(before) != string(after) {
					t.Fatal("restoration modified settings")
				}
			})
		}
	}
}

func mustImportedJSON(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestDesktopImportedExplicitLocalPreservesSavedExecutionAndLayers(t *testing.T) {
	for _, execution := range []string{"local", "server", "auto"} {
		for _, entryLayer := range []string{"off", "aes-256-gcm", "aes-256-gcm+xor-whitening"} {
			for _, exitLayer := range []string{"off", "aes-256-gcm", "aes-256-gcm+xor-whitening"} {
				t.Run(execution+"/"+entryLayer+"/"+exitLayer, func(t *testing.T) {
					root, initial := desktopImportedFixture(t, "shadowsocks", "reality-vision")
					if entryLayer != "off" {
						layered := desktopLayerProfile(t, "shadowsocks", entryLayer)
						initial.Entry.StartLayer, initial.Entry.External.StartLayer = entryLayer, layered.External.StartLayer
					}
					initial.Exit.StartLayer, initial.Exit.MultihopExecution = exitLayer, execution
					initial.Control = cloneRouterProfile(initial.Exit)
					q := multihopConnectRequest{EntryID: initial.Entry.ID, ExitID: initial.Exit.ID, ExitMode: initial.ExitMode, Execution: "local"}
					sel, err := resolveNativeMultihopSelection(initial.Control, []common.RouterProfile{initial.Entry, initial.Exit}, q)
					if err != nil {
						t.Fatal(err)
					}
					sel, err = captureNativeMultihopSelection(context.Background(), root, sel, []string{sel.ExitMode}, nil)
					if err != nil {
						t.Fatal(err)
					}
					if execution == "local" {
						emitDesktopImportedFixture(t, "layers-"+entryLayer+"--"+exitLayer+".json", []byte(sel.Native.configs[sel.ExitMode]))
					}
					if sel.Control.MultihopExecution != execution || sel.Exit.MultihopExecution != execution || sel.Entry.StartLayer != initial.Entry.StartLayer || sel.Exit.StartLayer != exitLayer {
						t.Fatal("Local candidate rewrote the saved execution or independent layers")
					}
					if execution != "local" {
						q.Execution = ""
						if _, err := resolveNativeMultihopSelection(initial.Control, []common.RouterProfile{initial.Entry, initial.Exit}, q); err == nil {
							t.Fatal("saved Server/Compare silently became Local")
						}
					}
				})
			}
		}
	}
}

func emitDesktopImportedFixture(t *testing.T, name string, config []byte) {
	t.Helper()
	if directory := os.Getenv("ROUTERVPN_IMPORTED_DESKTOP_FIXTURES"); directory != "" {
		if err := os.WriteFile(filepath.Join(directory, name), config, 0600); err != nil {
			t.Fatal("required imported desktop fixture was not emitted", err)
		}
	}
}

func TestDesktopImportedPhysicalEnvironmentUsesOnlyActualLayerSockets(t *testing.T) {
	for _, layer := range []string{"off", "aes-256-gcm", "aes-256-gcm+xor-whitening"} {
		t.Run(layer, func(t *testing.T) {
			root, sel := desktopImportedFixture(t, "shadowsocks", "reality-vision")
			physical := sel.Entry.Endpoint
			if layer != "off" {
				original := desktopLayerProfile(t, "shadowsocks", layer)
				sel.Entry.StartLayer, sel.Entry.External.StartLayer = layer, original.External.StartLayer
			}
			sel, err := captureNativeMultihopSelection(context.Background(), root, sel, []string{sel.ExitMode}, nil)
			if err != nil {
				t.Fatal(err)
			}
			launch, err := compileRetainedNativeMultihopLaunch(sel, nil)
			if err != nil {
				t.Fatal(err)
			}
			var metadata struct {
				ConfigSHA256 string `json:"config_sha256"`
			}
			if json.Unmarshal(launch.metadata, &metadata) != nil {
				t.Fatal("capture metadata")
			}
			launch.configSHA256, launch.mtuSession = metadata.ConfigSHA256, strings.Repeat("a", 32)
			launch.nodePhysicalCapture, err = captureDesktopNodePhysical(launch)
			if err != nil {
				t.Fatal(err)
			}
			environment, err := desktopNodePhysicalEnvironment(nativeMultihopEnvironment(root, sel), launch)
			if err != nil {
				t.Fatal(err)
			}
			values := map[string]string{}
			for _, raw := range environment {
				key, value, _ := strings.Cut(raw, "=")
				values[key] = value
			}
			if values["HOMEVPN_NODE_PHYSICAL_REQUIRED"] != "1" || values["HOMEVPN_ENDPOINT"] != physical || values["HOMEVPN_EXTERNAL_SESSION"] != "" || values["HOMEVPN_POLICY_PROFILE_ID"] != sel.Exit.ID || values["HOMEVPN_PROFILE_ID"] != sel.Entry.ID {
				t.Fatal("platform environment lost exact entry/final/physical ownership")
			}
			if strings.Contains(values["HOMEVPN_NATIVE_EGRESS_JSON"], sel.Exit.Endpoint) || strings.Contains(values["HOMEVPN_NATIVE_EGRESS_JSON"], "10.77.0.1") {
				t.Fatal("nonphysical inner peer gained exception")
			}
			if layer != "off" {
				for _, tuple := range launch.nodePhysicalEgress {
					if tuple.Host != physical || tuple.Port != 8389 {
						t.Fatal("original inner transport port escaped the selected Start Layer", tuple)
					}
				}
			}
			for _, raw := range desktopNativeEnvironment(environment, root, "new-node", "203.0.113.99") {
				if strings.HasPrefix(raw, "HOMEVPN_NODE_PHYSICAL_REQUIRED=") {
					t.Fatal("next node inherited imported path marker")
				}
			}
		})
	}
}

func TestDesktopImportedSavedProfileAddLoadUpdateDelete(t *testing.T) {
	desktopImportedSavedProfileAddLoadUpdateDelete(t, "socks5", "reality-vision")
}

func desktopImportedSavedProfileAddLoadUpdateDelete(t *testing.T, protocol, finalMode string) {
	t.Helper()
	root, sel := desktopImportedFixture(t, protocol, finalMode)
	t.Setenv("HOMEVPN_ROOT", root)
	t.Setenv("HOMEVPN_PORTABLE", "0")
	manifest := filepath.Join(root, "runtime", "native", "NATIVE-RUNTIME.json")
	if err := os.MkdirAll(filepath.Dir(manifest), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifest, []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	a := &app{cfg: common.ClientConfig{ProfilesFile: filepath.Join(root, "routers.json")}, profiles: common.RouterProfileStore{SchemaVersion: 4, SelectedID: sel.Exit.ID, Profiles: []common.RouterProfile{sel.Entry, sel.Exit}}, state: state{Mode: "off", Phase: "off"}}
	defer sessionTrackers.Delete(a)
	defer strategyLocks.Delete(a)
	if err := a.persistProfilesLocked(); err != nil {
		t.Fatal(err)
	}
	logicalMode := finalMode
	if finalMode == "wg" {
		logicalMode = "base-raw"
	}
	body := map[string]any{"name": "Imported to paired final", "mode": logicalMode, "multihop_enabled": true, "multihop_entry_id": sel.Entry.ID, "multihop_exit_id": sel.Exit.ID, "multihop_entry_mode": "", "multihop_exit_mode": sel.ExitMode, "multihop_execution": "local"}
	saved := postSetup(t, a, "/api/connection-profile/setup/save", body)
	if saved.Code != http.StatusOK {
		t.Fatal("save", saved.Code, saved.Body.String())
	}
	store, err := loadConnectionProfileStore(a)
	if err != nil || len(store.Profiles) != 1 || len(store.Profiles[0].Hops) != 1 || store.Profiles[0].Hops[0].External == nil {
		t.Fatal("save lost independent imported policy", err)
	}
	wantedPolicy, err := snapshotExternalConnectionPolicy(sel.Entry)
	if err != nil || !reflect.DeepEqual(store.Profiles[0].Hops[0].External, wantedPolicy) {
		t.Fatal("save changed independently captured imported policy", err)
	}
	id := store.Profiles[0].ID
	a.profiles.Profiles[0].DNSMode = "rescue"
	a.profiles.Profiles[1].MultihopEnabled = false
	loaded := postSetup(t, a, "/api/connection-profile/setup/load", map[string]any{"id": id})
	if loaded.Code != http.StatusOK {
		t.Fatal("load", loaded.Code, loaded.Body.String())
	}
	if a.profiles.Profiles[0].DNSMode != "home" || !a.profiles.Profiles[1].MultihopEnabled || a.profiles.SelectedID != sel.Exit.ID || a.state.Connected {
		t.Fatal("load lost original policy or changed connected state")
	}
	if !reflect.DeepEqual(a.profiles.Profiles[0].External, sel.Entry.External) || a.profiles.Profiles[1].APIToken != sel.Exit.APIToken {
		t.Fatal("load mixed original entry credentials with the paired final")
	}
	body["id"], body["name"] = id, "Updated imported path"
	if r := postSetup(t, a, "/api/connection-profile/setup/update", body); r.Code != http.StatusOK {
		t.Fatal("update", r.Code, r.Body.String())
	}
	for _, execution := range []string{"server", "auto"} {
		body["multihop_execution"] = execution
		if r := postSetup(t, a, "/api/connection-profile/setup/update", body); r.Code == http.StatusOK {
			t.Fatal("saved unavailable execution", execution)
		}
	}
	if r := postSetup(t, a, "/api/connection-profile/setup/delete", map[string]any{"id": id}); r.Code != http.StatusOK {
		t.Fatal(r.Code, r.Body.String())
	}
	store, err = loadConnectionProfileStore(a)
	if err != nil || len(store.Profiles) != 0 || len(a.profiles.Profiles) != 2 {
		t.Fatal("delete removed linked original nodes", err)
	}
	if !reflect.DeepEqual(a.profiles.Profiles[0].External, sel.Entry.External) || a.profiles.Profiles[1].APIToken != sel.Exit.APIToken {
		t.Fatal("delete changed independent node credentials")
	}
}

func TestDesktopImportedSelectionRejectsWrongDirectionExecutionAndMode(t *testing.T) {
	_, sel := desktopImportedFixture(t, "socks5", "reality-vision")
	profiles := []common.RouterProfile{sel.Entry, sel.Exit}
	request := multihopConnectRequest{EntryID: sel.Entry.ID, ExitID: sel.Exit.ID, EntryMode: sel.EntryMode, ExitMode: sel.ExitMode, Execution: "local"}
	if _, err := resolveNativeMultihopSelection(sel.Control, profiles, request); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"server", "auto", "wrong-entry-mode", "wrong-final", "third-control", "reverse"} {
		t.Run(kind, func(t *testing.T) {
			q, control := request, sel.Control
			switch kind {
			case "server", "auto":
				q.Execution = kind
			case "wrong-entry-mode":
				q.EntryMode = "wg"
			case "wrong-final":
				q.ExitMode = "max"
			case "third-control":
				control.ID = "unrelated"
			case "reverse":
				q.EntryID, q.ExitID = q.ExitID, q.EntryID
			}
			if _, err := resolveNativeMultihopSelection(control, profiles, q); err == nil {
				t.Fatal("unowned imported selection was admitted")
			}
		})
	}
}

func TestDesktopImportedCaptureRejectsFinalIdentityMutationAndCancellation(t *testing.T) {
	root, original := desktopImportedFixture(t, "shadowsocks", "shadowsocks")
	selected, err := captureNativeMultihopSelection(context.Background(), root, original, []string{original.ExitMode}, nil)
	if err != nil {
		t.Fatal(err)
	}
	changed := selected
	changed.Entry = cloneRouterProfile(selected.Entry)
	changed.Entry.External.Shadowsocks.Password = testWGKey('x')
	if selected.Native.validate(changed) == nil {
		t.Fatal("replacement imported credential retained source ownership")
	}
	path := filepath.Join(root, "generated", original.Exit.ID, "wg", "wg.conf")
	data, _ := os.ReadFile(path)
	if err := os.WriteFile(path, []byte(strings.Replace(string(data), testWGKey('r'), testWGKey('z'), 1)), 0600); err != nil {
		t.Fatal(err)
	}
	if selected.Native.validate(selected) == nil {
		t.Fatal("replacement paired bundle retained source ownership")
	}
	if _, err := captureNativeMultihopSelection(context.Background(), root, original, []string{original.ExitMode}, nil); err == nil {
		t.Fatal("wrong paired identity was accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := captureNativeMultihopSelection(ctx, root, original, []string{original.ExitMode}, nil); err == nil {
		t.Fatal("cancelled preparation reached launch")
	}
}

func TestDesktopImportedEntryPublicProofWrongIdentityCancelAndReplacement(t *testing.T) {
	desktopImportedEntryPublicProofWrongIdentityCancelAndReplacement(t, "shadowsocks")
}

func desktopImportedEntryPublicProofWrongIdentityCancelAndReplacement(t *testing.T, protocol string) {
	t.Helper()
	root, original := desktopImportedFixture(t, protocol, "shadowsocks")
	sel, err := captureNativeMultihopSelection(context.Background(), root, original, []string{original.ExitMode}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, fault := range []string{"wrong-public", "cancel", "replacement", "success"} {
		t.Run(fault, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
			defer cancel()
			owns, final := true, false
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "" {
					t.Error("private Router token sent to public entry proof")
				}
				value := sel.Entry.External.ExpectedPublicIP
				if fault == "wrong-public" {
					value = "203.0.113.234"
				}
				_, _ = w.Write([]byte(value))
			}))
			defer server.Close()
			err := proveNativeMultihopCapture(ctx, sel, func() bool { return owns }, func(ctx context.Context, profile common.RouterProfile, lane string) error {
				if profile.ID == sel.Entry.ID {
					if lane != multihopEntryProofProxy || profile.NodeProofID != "" {
						t.Fatal("entry borrowed final proof identity")
					}
					err := proveExpectedPublicExit(ctx, server.Client(), []string{server.URL}, profile.External.ExpectedPublicIP, "imported entry", time.Second)
					if fault == "cancel" {
						cancel()
					}
					if fault == "replacement" {
						owns = false
					}
					return err
				}
				final = true
				if lane != multihopProofProxy || profile.NodeProofID != sel.Exit.NodeProofID {
					t.Fatal("final proof changed")
				}
				return nil
			})
			if fault == "success" && (err != nil || !final) || fault != "success" && (err == nil || final) {
				t.Fatal("proof boundary lost cancellation or independent identity", fault, final, err)
			}
		})
	}
}
