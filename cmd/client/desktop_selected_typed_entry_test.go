package main

import (
	"context"
	"os"
	"path/filepath"
	"router-vpn/internal/common"
	"router-vpn/internal/mobilemultihop"
	"runtime"
	"testing"
	"time"
)

func selectedTypedEntryDraftFixture(t *testing.T, family, requested string) (*app, *multihopConnectRequest, orderedCandidatePreparationRequest) {
	t.Helper()
	var a *app
	var selection multihopSelection
	if family == "socks" {
		a, selection, _ = desktopSOCKSExecutionLayerPrefixFixture(4, "off", "off")(t, "wg", "windows")
	} else {
		var launch *desktopNodeLaunch
		a, launch = desktopCONNECTPrefixProductLaunchFixture(t, 2, "wg", "https-connect")
		selection = launch.chain.selection
	}
	original := clientRoot(a)
	pool, _ := desktopNodeChainCaptureFixture(t, 7)
	candidate := pool.profiles.Profiles[6]
	if _, found := a.profileByIDLocked(candidate.ID); found {
		t.Fatal("typed fixture candidate is already in selected route")
	}
	if err := os.CopyFS(filepath.Join(original, "generated", candidate.ID), os.DirFS(filepath.Join(clientRoot(pool), "generated", candidate.ID))); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOMEVPN_ROOT", original)
	a.profiles.Profiles = append(a.profiles.Profiles, common.CloneRouterProfile(candidate))
	return selectedDraftSourceFixture(t, a, nodeChainSelectedReferences(selection.Nodes), requested, 0, candidate.ID)
}

func TestDesktopSelectedTypedEntryOriginalDraft(t *testing.T) {
	for _, family := range []string{"socks", "connect"} {
		for _, outcome := range [][3]string{{"server", "server", "server"}, {"auto", "local", "compare-local"}, {"auto", "server", "compare-server"}} {
			t.Run(family+"/"+outcome[2], func(t *testing.T) {
				a, draft, q := selectedTypedEntryDraftFixture(t, family, outcome[0])
				observe := func(ctx context.Context) (string, error) { return "original-chain-physical-network", ctx.Err() }
				catalog, err := captureOrderedCandidatePreparedSelection(t.Context(), a, q.Position, q.Scope, draft, observe)
				if err != nil {
					t.Fatal("typed entry catalog", err)
				}
				if catalog.catalog.typedEntryPreview == nil || catalog.catalog.typedEntryPreview.Metadata() == "" || catalog.catalog.plan != nil || catalog.catalog.selectedPlan != nil || len(catalog.prefixes) != 1 || catalog.prefixes[0].Position != 0 {
					t.Fatal("typed entry acquired a generic plan or advertised a later position")
				}
				bad := q
				bad.Position = 1
				if _, err := captureOrderedCandidatePreparedSelection(t.Context(), a, 1, q.Scope, draft, observe); err == nil {
					t.Fatal("typed source included a later packet or stream position")
				}
				if p, err := beginOrderedCandidatePreparationWithNetwork(t.Context(), a, bad, observe); err == nil {
					_ = p.finish()
					t.Fatal("typed source started a later packet or stream position")
				}
				testOriginalSelectedDraftLifecycle(t, a, draft, q, outcome)
			})
		}
	}
}

func TestDesktopSelectedTypedEntryConnected(t *testing.T) {
	for _, family := range []string{"socks", "connect"} {
		for _, outcome := range [][3]string{{"server", "server", "server"}, {"auto", "local", "compare-local"}, {"auto", "server", "compare-server"}} {
			t.Run(family+"/"+outcome[2], func(t *testing.T) {
				var f *desktopNodeChainOwnedFixture
				var session *desktopNodeChainExecutionSession
				if family == "socks" {
					f, session = prepareDesktopSOCKSExecutionModelFixture(t, outcome[0], outcome[1], desktopSOCKSExecutionLayerPrefixFixture(4, "off", "off"))
				} else {
					f, session = prepareDesktopCONNECTExecutionModelFixture(t, outcome[0], outcome[1], func(t *testing.T) (*app, *desktopNodeLaunch) {
						return desktopCONNECTPrefixProductLaunchFixture(t, 2, "wg", "https-connect")
					})
				}
				if err := session.startContext(f.operation); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
					defer cancel()
					if err := retireDesktopOrderedLatencyFixture(ctx, f.a, f.launch.command); err != nil {
						t.Error(err)
					}
				})
				f.a.cfg.StateFile = filepath.Join(clientRoot(f.a), "selected-typed-candidate-state.json")
				f.a.mu.Lock()
				f.a.state.Connected, f.a.state.Phase = true, "connected"
				f.a.mu.Unlock()
				sessionTrackers.Store(f.a, &sessionTracker{a: f.a, session: &connectionSession{ID: "session-1-1", Connected: true, Phase: "connected", PathProof: "passed", RouterID: f.selection.Control.ID}})
				e := session.execution
				e.mu.Lock()
				ready, projection := *e.ready, e.projection
				e.mu.Unlock()
				publishDesktopSelectedDraftCapture(t, f.launch, e.preparation, projection, ready, outcome[1])
				id := desktopCandidateAddCustomSource(t, f.a, "2022-blake3-aes-256-gcm")
				identity, _, err := captureSpeedLabIdentityContext(t.Context(), f.a)
				if err != nil {
					t.Fatal(err)
				}
				identity.Tracker.mu.Lock()
				if identity.Tracker.dnsProofRunning || identity.Tracker.dnsProofWork != nil {
					identity.Tracker.mu.Unlock()
					t.Fatal("typed candidate lost idle DNS proof")
				}
				identity.Tracker.dnsProofRunning = true
				identity.Tracker.mu.Unlock()
				c, err := captureDesktopNodeChainCandidates(t.Context(), f.a, identity, 0, []string{id})
				if err != nil || c.selectedPlan == nil || c.typedPlan != nil || c.plan != nil || c.typedEntryPreview != nil {
					t.Fatal("connected original typed entry descriptor", err)
				}
				if !mobilemultihop.NodeChainPrefixMode(f.selection.Nodes[1].Mode) {
					t.Fatal("missing paired interior refusal control")
				}
				if _, err := captureDesktopNodeChainCandidates(t.Context(), f.a, identity, 1, []string{id}); err == nil {
					t.Fatal("connected typed source granted a later position")
				}
				var replaySOCKS *mobilemultihop.DesktopNodeChainSOCKSPolicy
				var replayCONNECT *mobilemultihop.DesktopNodeChainCONNECTPolicy
				if family == "socks" {
					input, e := e.original.socksPolicy.LaunchInput()
					if e != nil {
						t.Fatal(e)
					}
					replaySOCKS, err = mobilemultihop.ParseDesktopNodeChainSOCKSLaunchInput(input)
				} else {
					input, e := e.original.connectPolicy.LaunchInput()
					if e != nil {
						t.Fatal(e)
					}
					replayCONNECT, err = mobilemultihop.ParseDesktopNodeChainCONNECTLaunchInput(input)
				}
				if err != nil {
					t.Fatal(err)
				}
				if _, err := e.preparation.DescribeDesktopTypedEntryCandidate(replaySOCKS, replayCONNECT, 0, c.inventory); err == nil {
					t.Fatal("equal source bytes substituted for original typed authority")
				}
				exerciseDesktopSelectedCandidateHTTP(t, f, c, id, outcome[1], 0, []int{0})
			})
		}
	}
}

func TestDesktopCandidatePinsOriginalPrivateReadPermission(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows authenticates the private file ACL instead of Unix mode bits")
	}
	for _, change := range []string{"original", "same-bytes-foreign-inode", "unexpected-mode", "mode-after-admission"} {
		t.Run(change, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "paired")
			data := []byte("existing paired source")
			if err := os.WriteFile(path, data, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, 0o644); err != nil {
				t.Fatal(err)
			}
			before, err := os.Lstat(path)
			if err != nil {
				t.Fatal(err)
			}
			catalog := &desktopNodeChainCandidateCatalog{launch: &desktopNodeLaunch{}, files: []desktopCandidateSourceFile{{path, before}}}
			if _, err := readPrivateRegular(path, 4096); err != nil {
				t.Fatal(err)
			}
			switch change {
			case "same-bytes-foreign-inode":
				replacement := path + ".replacement"
				if err := os.WriteFile(replacement, data, 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Chtimes(replacement, before.ModTime(), before.ModTime()); err != nil {
					t.Fatal(err)
				}
				if err := os.Rename(replacement, path); err != nil {
					t.Fatal(err)
				}
			case "unexpected-mode":
				if err := os.Chmod(path, 0o400); err != nil {
					t.Fatal(err)
				}
			}
			err = catalog.pinPrivateReadPermissions(t.Context())
			if change == "same-bytes-foreign-inode" || change == "unexpected-mode" {
				if err == nil {
					t.Fatal("changed original source accepted after private read")
				}
				return
			}
			if err != nil || catalog.files[0].info.Mode() != 0o600 || catalog.sourceFilesCurrent(t.Context()) != nil {
				t.Fatal("original private read lost its pinned source", err)
			}
			if change == "mode-after-admission" {
				if err := os.Chmod(path, 0o644); err != nil {
					t.Fatal(err)
				}
				if err := catalog.sourceFilesCurrent(t.Context()); err == nil {
					t.Fatal("a later permission change retained the original source")
				}
			}
		})
	}
}
