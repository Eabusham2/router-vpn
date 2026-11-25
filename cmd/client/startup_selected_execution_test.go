package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"router-vpn/internal/common"
	"router-vpn/internal/mobilemultihop"
)

func TestSelectedStartupKeepsOriginalChildChoice(t *testing.T) {
	testSelectedStartupKeepsOriginalChildChoice(t, false)
}

func TestSelectedPrivateStartupKeepsOriginalChildChoice(t *testing.T) {
	testSelectedStartupKeepsOriginalChildChoice(t, true)
}

func testSelectedStartupKeepsOriginalChildChoice(t *testing.T, private bool) {
	if runtime.GOOS != "linux" && runtime.GOOS != "windows" {
		t.Skip("requires typed public desktop admission")
	}
	for _, choice := range []struct{ requested, winner string }{{"server", "server"}, {"auto", "local"}, {"auto", "server"}} {
		t.Run(choice.requested+"-"+choice.winner, func(t *testing.T) {
			layout := desktopIndependentSelectedLayouts()
			original := layout[len(layout)-1]
			a, refs := desktopIndependentImportedFixture(t, original, "wg", "off")
			if private {
				original.count = 9
				a, refs = desktopSelectedPrivateStreamFixture(t, original.count, 4)
			}
			a.cfg.StateFile = filepath.Join(clientRoot(a), "startup-receipts", "selected.json")
			control := &a.profiles.Profiles[len(a.profiles.Profiles)-1]
			control.AutoConnect, control.StartupMode, control.MultihopExecution = true, "auto", choice.requested
			control.MultihopEnabled = true
			control.MultihopNodes = refs
			a.profiles.SelectedID = control.ID
			selection, err := resolveDesktopNodeChainSelection(*control, a.profiles.Profiles, refs, choice.requested)
			if err != nil {
				t.Fatal(err)
			}
			selection, err = captureNativeNodeChainSelection(t.Context(), clientRoot(a), selection, []string{"shadowsocks"}, nil)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { desktopOrderedExecutionOwners.Delete(a); desktopComparisons.Delete(a) })
			f := newDesktopNodeChainOwnedFixtureWith(t, a, selection)
			f.executionModel = &desktopExecutionOwnedModel{winner: choice.winner}
			a.state.Mode, a.state.Phase = "off", "off"
			release, err := a.holdCapturedMTU(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			defer release()
			fresh := startupNodeChainCaptureForTest(t, a)
			if fresh.nodeChain.requested != choice.requested || fresh.nodeChain.selectedLast != "" {
				t.Fatal("scheduled selection changed")
			}
			prepare := func(ctx context.Context, owner *app, sel multihopSelection, requested, saved string) (*desktopNodeChainExecutionSession, error) {
				request := &desktopNodeChainExecutionRequest{capture: f.capture, native: sel.Native, requested: requested, startupLast: saved}
				launch, err := prepareDesktopOwnedNodeChainLaunchForPurposeAndExecution(ctx, f.capture, sel, nil, request)
				if err != nil {
					return nil, err
				}
				f.launch = launch
				return &desktopNodeChainExecutionSession{app: owner, launch: launch, execution: launch.chain.execution, selection: sel}, nil
			}
			driver := desktopOrderedExecutionRuntime{capture: func(ctx context.Context, _ *app, sel multihopSelection, modes []string) (multihopSelection, error) {
				if !reflect.DeepEqual(nodeChainSelectedReferences(sel.Nodes), refs) {
					t.Fatal("selected startup replaced original refs")
				}
				return selection, ctx.Err()
			}, prepare: func(ctx context.Context, a *app, s multihopSelection, requested string) (*desktopNodeChainExecutionSession, error) {
				return prepare(ctx, a, s, requested, "")
			}, prepareLast: prepare}
			if err := a.startNodeChainStartupOwned(f.operation, fresh, nativeMultihopConnectRuntime{execution: &driver}); err != nil {
				t.Fatal("selected startup", err)
			}
			published, err := a.loadStartupSelection()
			if err != nil || published.NodeChain == nil {
				t.Fatal("missing published selected startup Last", err)
			}
			owner, err := a.desktopOrderedExecutionOwner()
			if err != nil || owner == nil {
				t.Fatal(err)
			}
			record, err := mobilemultihop.ParseNodeChainExecutionLast(published.NodeChain.SelectedLast, owner.session.execution.preparation)
			if err != nil || record.Execution() != choice.winner || record.Target() != owner.session.execution.ready.Progress.Comparison.Target || len(published.NodeChain.Nodes) != original.count {
				t.Fatal("published startup lost source, original target or winner", err)
			}
			if _, err := captureStartupNodeChain(a, *control, a.profiles.Profiles, &published); err == nil {
				t.Fatal("selected choice fell through Local capture")
			}
			if err := owner.session.Close(t.Context()); err != nil {
				t.Fatal(err)
			}
			desktopOrderedExecutionOwners.Delete(a)
			control = &a.profiles.Profiles[len(a.profiles.Profiles)-1]
			control.StartupMode = "last"
			for _, mutation := range []struct {
				name     string
				position int
				change   func(*common.RouterProfile)
			}{
				{"late profile identity", len(refs) - 2, func(p *common.RouterProfile) { p.ID += "-changed" }},
				{"late imported credential", len(refs) - 2, func(p *common.RouterProfile) { p.External.Shadowsocks.Password += "x" }},
				{"late Start Layer", len(refs) - 1, func(p *common.RouterProfile) { p.StartLayer = "aes-256-gcm" }},
				{"current manual MTU policy", len(refs) - 1, func(p *common.RouterProfile) { p.MTUPolicy = "fixed"; p.ManualMTU = 1312 }},
			} {
				p := &a.profiles.Profiles[mutation.position]
				before := cloneRouterProfile(*p)
				mutation.change(p)
				if changed, err := a.captureStartupPolicy(); err == nil || changed != nil {
					t.Fatalf("selected startup borrowed %s", mutation.name)
				}
				*p = before
			}
			replay := startupNodeChainCaptureForTest(t, a)
			if replay.nodeChain.selectedLast != record.JSON() {
				t.Fatal("Last did not retain the original native choice")
			}
			resolved, err := captureNativeNodeChainSelection(replay.nodeChain.compilerContext(t.Context()), clientRoot(a), replay.nodeChain.selection, []string{"shadowsocks"}, nil)
			if err != nil {
				t.Fatal(err)
			}
			// A restarted controller acquires new concrete host and private file owners.
			restarted := newDesktopNodeChainOwnedFixtureWith(t, a, resolved)
			restarted.executionModel = &desktopExecutionOwnedModel{winner: choice.winner}
			f = restarted
			selection = resolved
			freshPrepare := driver.prepare
			driver.prepare = func(context.Context, *app, multihopSelection, string) (*desktopNodeChainExecutionSession, error) {
				t.Fatal("Last reran fresh Compare/Server")
				return nil, nil
			}
			if err := a.startNodeChainStartupOwned(f.operation, replay, nativeMultihopConnectRuntime{execution: &driver}); err != nil {
				t.Fatal("native Last startup", err)
			}
			owner, err = a.desktopOrderedExecutionOwner()
			if err != nil || owner == nil || owner.session.execution.ready.Progress.Execution != choice.winner || owner.session.execution.ready.Progress.Comparison.Target != record.Target() {
				t.Fatal("new active child changed frozen choice", err)
			}
			if err := owner.session.Close(t.Context()); err != nil {
				t.Fatal(err)
			}
			if choice.requested == "auto" && choice.winner == "local" {
				t.Run("failed-Last-write-retires-new-Server-and-keeps-Local", func(t *testing.T) {
					desktopOrderedExecutionOwners.Delete(a)
					path := a.startupStatePath()
					oldLast, err := os.ReadFile(path)
					if err != nil {
						t.Fatal(err)
					}
					prior, err := a.loadStartupSelection()
					if err != nil || prior.NodeChain == nil {
						t.Fatal("missing original saved Last", err)
					}
					var frozen struct {
						Execution string `json:"execution"`
						Target    string `json:"target"`
					}
					if err := json.Unmarshal([]byte(prior.NodeChain.SelectedLast), &frozen); err != nil || frozen.Execution != "local" || frozen.Target != record.Target() {
						t.Fatal("incorrect prior frozen choice", err)
					}
					a.profiles.Profiles[len(a.profiles.Profiles)-1].StartupMode = "auto"
					if err := a.persistProfilesLocked(); err != nil {
						t.Fatal(err)
					}
					beforeStore := cloneRouterProfileStore(a.profiles)
					diskBefore, err := os.ReadFile(a.cfg.ProfilesFile)
					if err != nil {
						t.Fatal(err)
					}
					fresh := startupNodeChainCaptureForTest(t, a)
					selection, err = captureNativeNodeChainSelection(t.Context(), clientRoot(a), fresh.nodeChain.selection, []string{"shadowsocks"}, nil)
					if err != nil {
						t.Fatal(err)
					}
					f = newDesktopNodeChainOwnedFixtureWith(t, a, selection)
					f.executionModel = &desktopExecutionOwnedModel{winner: "server"}
					driver.prepare = freshPrepare
					// The prior private store still exists. Make its configured
					// parent temporarily unavailable without touching that Last.
					dir := filepath.Dir(path)
					offline := dir + "-offline"
					if err := os.Rename(dir, offline); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(dir, []byte("unavailable"), 0600); err != nil {
						t.Fatal(err)
					}
					err = a.startNodeChainStartupOwned(f.operation, fresh, nativeMultihopConnectRuntime{execution: &driver})
					if err == nil || !strings.Contains(err.Error(), "could not commit selected startup Last") {
						t.Fatal("connection ignored or missed original storage failure", err)
					}
					if f.executionModel.ready.Progress.Execution != "server" || a.state.Connected || a.state.Phase != "off" || a.cmd != nil {
						t.Fatal("failed Last left an unreported native connection", a.state.Phase)
					}
					if _, active := getActiveMultihopGraph(a); active {
						t.Fatal("failed native graph remained published")
					}
					diskAfter, err := os.ReadFile(a.cfg.ProfilesFile)
					if err != nil || !bytes.Equal(diskBefore, diskAfter) || !reflect.DeepEqual(beforeStore, a.profiles) {
						t.Fatal("failed publication retained usage", err)
					}
					if err := os.Remove(dir); err != nil {
						t.Fatal(err)
					}
					if err := os.Rename(offline, dir); err != nil {
						t.Fatal(err)
					}
					retained, err := os.ReadFile(path)
					if err != nil || !bytes.Equal(retained, oldLast) {
						t.Fatal("new failed winner displaced original saved Last", err)
					}
					a.profiles.Profiles[len(a.profiles.Profiles)-1].StartupMode = "last"
					originalReplay := startupNodeChainCaptureForTest(t, a)
					if originalReplay.nodeChain.selectedLast != prior.NodeChain.SelectedLast {
						t.Fatal("failed connection changed the original replayable Local winner")
					}
				})
			}
		})
	}
}

func TestSelectedStartupCompilerKeepsLivePolicy(t *testing.T) {
	original := common.RouterProfile{ID: "original", EffectiveMTU: 1320, UseCount: 1}
	current := cloneRouterProfile(original)
	current.EffectiveMTU, current.UseCount, current.ManualMTU = 1290, 4, 1340
	current.StartLayer, current.APIToken = "aes-256-gcm", "live-private-credential"
	raw, err := startupCompilerHistory(original)
	if err != nil {
		t.Fatal(err)
	}
	compiled, err := withStartupCompilerHistory(current, raw)
	if err != nil || compiled.EffectiveMTU != original.EffectiveMTU || current.EffectiveMTU != 1290 || compiled.ManualMTU != current.ManualMTU || compiled.StartLayer != current.StartLayer || compiled.APIToken != current.APIToken {
		t.Fatal("compiler history displaced current data-plane authority", err)
	}
	for _, foreign := range []string{`{"ManualMTU":9000}`, `{"APIToken":"foreign"}`, `{"FastestDNSHost":"foreign"}`, `{"StartLayer":""}`, `{"External":{}}`} {
		if _, err := withStartupCompilerHistory(current, foreign); err == nil {
			t.Fatal("foreign compiler history became authority")
		}
	}
	if assets, err := originalStartupNodeChainAssets(multihopSelection{}); err == nil || assets != nil {
		t.Fatal("uncaptured selection returned private inventory")
	}
}
