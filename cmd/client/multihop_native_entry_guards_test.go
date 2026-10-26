package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"router-vpn/internal/common"
	"router-vpn/internal/mobilemultihop"
)

func TestNativeEntryMultihopCapturedSourcesAndProofOwnership(t *testing.T) {
	for _, mode := range mobilemultihop.NodeMultihopEntryModes() {
		t.Run(mode, func(t *testing.T) {
			root, selected := nativeEntryMultihopFixture(t, mode, "off")
			selected, err := captureNativeMultihopSelection(context.Background(), root, selected, []string{"shadowsocks"}, nil)
			if err != nil {
				t.Fatal(err)
			}
			for _, fault := range []string{"entry-mode", "base", "control-policy", "entry-node", "exit-node", "entry-credential", "exit-dns"} {
				bad := selected
				bad.Control, bad.Entry, bad.Exit = common.CloneRouterProfile(selected.Control), common.CloneRouterProfile(selected.Entry), common.CloneRouterProfile(selected.Exit)
				switch fault {
				case "entry-mode":
					bad.EntryMode = "foreign-mode"
				case "base":
					bad.Base = "auto"
				case "control-policy":
					bad.Control.MultihopEntryMode = "foreign-mode"
				case "entry-node":
					bad.Entry.NodeProofID = strings.Repeat("f", 64)
				case "exit-node":
					bad.Exit.NodeProofID = strings.Repeat("f", 64)
				case "entry-credential":
					bad.Entry.APIToken = "relinked-private-node"
				case "exit-dns":
					bad.Exit.DNSMode = "system"
				}
				if _, err := compileRetainedNativeMultihopLaunch(bad, nil); err == nil {
					t.Fatal("captured graph accepted changed", fault)
				}
			}
			for _, retired := range []bool{false, true} {
				owned, calls := true, 0
				err := proveNativeMultihopCapture(context.Background(), selected, func() bool { return owned }, func(_ context.Context, p common.RouterProfile, proxy string) error {
					calls++
					if calls == 1 && (p.ID != selected.Entry.ID || proxy != multihopEntryProofProxy) || calls == 2 && (p.ID != selected.Exit.ID || proxy != multihopProofProxy) {
						t.Fatal("proof ran against another captured node or path")
					}
					if retired && calls == 1 {
						owned = false
					}
					return nil
				})
				if retired && (err == nil || calls != 1) || !retired && (err != nil || calls != 2) {
					t.Fatal("retired entry callback reached another node or fresh proof failed", retired, calls, err)
				}
			}
			files, err := readDesktopNodeAssets(root, selected.Entry.ID, mode)
			if err != nil {
				t.Fatal(err)
			}
			var name string
			for key := range files {
				name = key
				break
			}
			path := filepath.Join(root, "generated", selected.Entry.ID, mode, name)
			original := append([]byte(nil), files[name]...)
			clearViaEntryAssets(files)
			if err := os.WriteFile(path, append(append([]byte(nil), original...), byte('\n')), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := compileRetainedNativeMultihopLaunch(selected, nil); err == nil {
				t.Fatal("changed raw entry bytes reused a proved immutable capture")
			}
			if err := os.WriteFile(path, original, 0600); err != nil {
				t.Fatal(err)
			}
			clear(original)
			if _, err := compileRetainedNativeMultihopLaunch(selected, nil); err != nil {
				t.Fatal("exact restored source lost its capture", err)
			}
		})
	}
}

func TestNativeEntryMultihopServerCannotDiscardCapturedClosure(t *testing.T) {
	for _, mode := range []string{"split", "naive-h3", "max-quic-awg"} {
		t.Run(mode, func(t *testing.T) {
			root, selected := nativeEntryMultihopFixture(t, mode, "aes-256-gcm+xor-whitening")
			selected, err := captureNativeMultihopSelection(context.Background(), root, selected, []string{"shadowsocks"}, nil)
			if err != nil {
				t.Fatal(err)
			}
			graph := retainedGraph(t, []byte(selected.Native.configs["shadowsocks"]))
			_, original, err := nativeMultihopEntrySnapshot(graph, selected.Native.entryOwners)
			if err != nil {
				t.Fatal(err)
			}
			defer clear(original)
			for _, fault := range []string{"missing-node", "duplicate-node", "foreign-detour", "foreign-extra", "missing-resolver", "resolver-escape", "foreign-service"} {
				copy := retainedGraph(t, []byte(selected.Native.configs["shadowsocks"]))
				switch fault {
				case "missing-node", "duplicate-node", "foreign-detour":
					changed := false
					for _, family := range []string{"outbounds", "endpoints"} {
						rows, _ := copy[family].([]any)
						for i, row := range rows {
							n := row.(map[string]any)
							if n["tag"] != "entry-wg" {
								continue
							}
							switch fault {
							case "missing-node":
								copy[family] = append(rows[:i], rows[i+1:]...)
							case "duplicate-node":
								copy[family] = append(rows, n)
							case "foreign-detour":
								n["detour"] = "proxy"
							}
							changed = true
							break
						}
					}
					if !changed {
						t.Fatal("negative did not mutate entry root")
					}
				case "foreign-extra":
					copy["outbounds"] = append(copy["outbounds"].([]any), map[string]any{"type": "direct", "tag": "external-entry-node-foreign"})
				case "missing-resolver", "resolver-escape":
					dns := copy["dns"].(map[string]any)
					rows := dns["servers"].([]any)
					changed := false
					for i, row := range rows {
						resolver := row.(map[string]any)
						if !strings.HasPrefix(resolver["tag"].(string), "external-entry-dns-") {
							continue
						}
						if fault == "missing-resolver" {
							dns["servers"] = append(rows[:i], rows[i+1:]...)
						} else {
							resolver["detour"] = "proxy"
						}
						changed = true
						break
					}
					if !changed {
						t.Fatal("negative had no entry resolver")
					}
				case "foreign-service":
					changed := false
					for _, row := range copy["services"].([]any) {
						service := row.(map[string]any)
						if service["tag"] == "routervpn-cover-entry" {
							service["proof_tag"] = "proxy"
							changed = true
						}
					}
					if !changed {
						t.Fatal("negative had no cover owner")
					}
				}
				if _, body, err := nativeMultihopEntrySnapshot(copy, selected.Native.entryOwners); err == nil {
					clear(body)
					t.Fatal("partial or foreign entry closure accepted", fault)
				}
				_, descriptor := executionFixture()
				descriptor.Lease.ExitMode = "shadowsocks"
				descriptor.Lease.ExitStartLayer = selected.Exit.StartLayer
				raw, _ := json.Marshal(copy)
				if _, err := compileDesktopExecutionConfig(raw, descriptor, selected); err == nil {
					t.Fatal("Server accepted changed captured bytes", fault)
				}
			}
			// Exact private field changes remain part of the before/after comparison;
			// a public tag inventory alone cannot bless substituted node credentials.
			copy := retainedGraph(t, []byte(selected.Native.configs["shadowsocks"]))
			for _, row := range copy["dns"].(map[string]any)["servers"].([]any) {
				resolver := row.(map[string]any)
				if strings.HasPrefix(resolver["tag"].(string), "external-entry-dns-") {
					resolver["server"] = "changed-resolver.example"
					break
				}
			}
			_, changed, err := nativeMultihopEntrySnapshot(copy, selected.Native.entryOwners)
			defer clear(changed)
			if err != nil || bytes.Equal(original, changed) {
				t.Fatal("entry snapshot failed to bind exact policy bytes")
			}
		})
	}
}

func TestNativeEntryMultihopSpeedLabRetainsRawModeWinnerAndReadback(t *testing.T) {
	for _, mode := range []string{"hysteria2", "naive-h3", "split", "max-quic-awg"} {
		for _, execution := range []string{"local", "server"} {
			t.Run(mode+"/"+execution, func(t *testing.T) {
				f := newRetainedMultihopModeFixture(t, execution, "shadowsocks", mode)
				t.Setenv("HOMEVPN_ROOT", f.launch.root)
				receipt := filepath.Join(f.launch.root, "runtime", "native", "NATIVE-RUNTIME.json")
				if err := os.MkdirAll(filepath.Dir(receipt), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(receipt, []byte(`{}`), 0600); err != nil {
					t.Fatal(err)
				}
				snapshot := speedLabTemporarySnapshot{Profiles: cloneRouterProfileStore(f.a.profiles), State: f.a.state, Runtime: f.a.cmd}
				plan, err := f.a.speedLabCaptureRestorePlan(snapshot)
				if err != nil {
					t.Fatal(err)
				}
				if plan.multihop == nil || plan.multihop.Native != f.selection.Native || plan.multihop.EntryMode != mode || plan.multihop.Base != "native" || plan.multihop.restoreMTU != 1360 || plan.request.EntryMode != mode || plan.request.Execution != execution || plan.request.Base != "native" || plan.multihop.Control.MultihopExecution != "auto" {
					t.Fatal("Speed Lab reran selection or lost the captured entry/MTU")
				}
				before := common.CloneRouterProfile(plan.multihop.Entry)
				f.a.profiles.Profiles[1].MultihopEntryMode = "wg"
				if !reflect.DeepEqual(before, plan.multihop.Entry) {
					t.Fatal("restore borrowed mutable node preferences")
				}
				if _, err := f.a.speedLabCaptureRestorePlan(snapshot); err == nil {
					t.Fatal("relinked current entry was accepted for another restoration")
				}
			})
		}
	}
}

func TestNativeEntryMultihopExplicitAWGDoesNotRediscoverAnotherVariant(t *testing.T) {
	for _, explicit := range []bool{false, true} {
		t.Run(map[bool]string{false: "legacy-fallback", true: "explicit-strong"}[explicit], func(t *testing.T) {
			root, selected := nativeEntryMultihopFixture(t, "awg2-strong", "off")
			if !explicit {
				selected.EntryMode = ""
				selected.Control.MultihopEntryMode = ""
			}
			captured, err := captureNativeMultihopSelection(context.Background(), root, selected, []string{"shadowsocks"}, nil)
			if err != nil {
				t.Fatal(err)
			}
			if captured.EntryMode != "awg2-strong" {
				t.Fatal("wrong initial AWG fixture")
			}
			_, files := viaEntryBaseFixture(t, "awg2-fast")
			dir := filepath.Join(root, "generated", selected.Entry.ID, "awg2-fast")
			if err := os.MkdirAll(dir, 0700); err != nil {
				t.Fatal(err)
			}
			for name, data := range files {
				if err := os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
					t.Fatal(err)
				}
			}
			err = captured.Native.validate(captured)
			if explicit && err != nil || !explicit && err == nil {
				t.Fatal("raw AWG selection was rediscovered or legacy fallback changed without rejection", explicit, err)
			}
		})
	}
}

func TestNativeEntryMultihopTemporaryDefaultsRemainWithControlSelection(t *testing.T) {
	a := desktopSpeedLabFormApp(t)
	entry, _ := profileByID(a.profiles.Profiles, "entry")
	selected := common.CloneRouterProfile(entry)
	selected.ID, selected.MultihopEntryMode = "saved-control", "reality-xhttp"
	entry.MultihopEntryMode = "max-quic-awg"
	profiles := append([]common.RouterProfile{selected}, a.profiles.Profiles...)
	for i := range profiles {
		if profiles[i].ID == entry.ID {
			profiles[i] = entry
		}
	}
	q := speedLabRequest{EntryID: entry.ID, ExitID: "exit-router", ExitMode: "shadowsocks", Execution: "auto"}
	resolved, err := a.resolveSpeedLabTemporaryMultihop(q, selected, entry, profiles)
	if err != nil || resolved.EntryMode != "reality-xhttp" || resolved.Base != "native" || !reflect.DeepEqual(resolved.Control, entry) {
		t.Fatal("temporary profile mutation borrowed its hop's different saved graph", err)
	}
	selected.MultihopEntryMode = ""
	resolved, err = a.resolveSpeedLabTemporaryMultihop(q, selected, entry, profiles)
	if err != nil || resolved.EntryMode != "" || resolved.Base != "awg" || !reflect.DeepEqual(resolved.Control, entry) {
		t.Fatal("empty control selection guessed a new raw entry instead of legacy base", err)
	}
	q.EntryMode = "wg"
	resolved, err = a.resolveSpeedLabTemporaryMultihop(q, selected, entry, profiles)
	if err != nil || resolved.EntryMode != "wg" || resolved.Base != "wg" {
		t.Fatal("explicit form raw mode was replaced by saved metadata", err)
	}
}
