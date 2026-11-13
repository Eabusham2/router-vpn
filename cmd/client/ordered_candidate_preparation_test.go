package main

import (
	"context"
	"errors"
	"os/exec"
	"reflect"
	"strings"
	"testing"
	"testing/synctest"
	"time"
)

func orderedPreparationFixture(t *testing.T, mode string) (*app, orderedCandidatePreparationRequest) {
	t.Helper()
	a, nodes := desktopNodeChainCaptureFixture(t, 3)
	for i := range a.profiles.Profiles {
		a.profiles.Profiles[i].KillSwitch, a.profiles.Profiles[i].KillSwitchPolicy = true, "on-connect"
	}
	if mode != "wg" {
		installOrderedAWGAssets(t, a, nodes, []string{mode, "wg", "shadowsocks"}, "off")
	}
	a.state.Connected, a.state.Mode, a.state.Phase = false, "off", "off"
	id := desktopCandidateAddCustomSource(t, a, "2022-blake3-aes-256-gcm")
	return a, orderedCandidatePreparationRequest{RequestID: strings.Repeat("a", 32), Position: 0, CandidateIDs: []string{id}, Samples: 50}
}

func beginOrderedPreparationFixture(t *testing.T, a *app, q orderedCandidatePreparationRequest) *orderedCandidatePreparation {
	t.Helper()
	p, err := beginOrderedCandidatePreparationWithNetwork(context.Background(), a, q, func(ctx context.Context) (string, error) { return "original-physical-network", ctx.Err() })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.finish() })
	return p
}

func bindOrderedPreparationFixture(t *testing.T, p *orderedCandidatePreparation) *desktopNodeLaunch {
	t.Helper()
	launch, err := newDesktopNodeChainLaunch(p.selection, strings.Repeat("b", 32), "windows")
	if err != nil {
		t.Fatal(err)
	}
	if err := p.bindLaunch(context.Background(), launch); err != nil {
		t.Fatal(err)
	}
	return launch
}

func TestOrderedCandidatePreparationCapturesSavedGraphWithoutConnectedAuthority(t *testing.T) {
	for _, mode := range []string{"wg", "awg2-fast", "awg2-strong"} {
		t.Run(mode, func(t *testing.T) {
			a, q := orderedPreparationFixture(t, mode)
			before, state := cloneRouterProfileStore(a.profiles), a.state
			p := beginOrderedPreparationFixture(t, a, q)
			q.CandidateIDs[0] = "changed-caller-slice"
			if p.request.CandidateIDs[0] == q.CandidateIDs[0] || !reflect.DeepEqual(before, a.profiles) || a.state != state || a.cmd != nil {
				t.Fatal("preparation changed saved preferences/history/Home or retained mutable caller IDs")
			}
			if p.selection.EntryMode != mode || len(p.selection.Nodes) != 3 || p.inventory.identity.Ordered != nil || p.inventory.launch.command != nil || p.inventory.launch.chain.ready != nil {
				t.Fatal("source-only capture invented a connected proof or lost the complete saved graph")
			}
			if p.inventory.current(context.Background()) == nil {
				t.Fatal("source-only inventory passed connected catalog admission")
			}
			if _, _, _, err := captureOrderedPerformanceContext(context.Background(), a); err == nil {
				t.Fatal("preparation granted connected Performance authority")
			}
			if err := p.sourceCurrent(context.Background()); err != nil {
				t.Fatal(err)
			}
			launch := bindOrderedPreparationFixture(t, p)
			a.mu.Lock()
			purpose, err := orderedCandidateLaunchPurposeLocked(a, launch)
			a.mu.Unlock()
			if err != nil || purpose != p {
				t.Fatal("fresh launch did not retain exact immutable purpose", err)
			}
			if err := p.bindLaunch(context.Background(), launch); err == nil {
				t.Fatal("purpose could be rebound")
			}
			other, err := newDesktopNodeChainLaunch(p.selection, strings.Repeat("c", 32), "windows")
			if err != nil {
				t.Fatal(err)
			}
			a.mu.Lock()
			_, err = orderedCandidateLaunchPurposeLocked(a, other)
			a.mu.Unlock()
			if err == nil {
				t.Fatal("temporary operation fell through to an ordinary unbound launch")
			}
			if err := p.finish(); err != nil {
				t.Fatal(err)
			}
			if a.candidatePreparation != nil || a.connectionContext != nil || !p.owner.drained || !p.down || a.state != state || !reflect.DeepEqual(before, a.profiles) {
				t.Fatal("unused preparation did not retire without profile/history/Home mutation")
			}
		})
	}
}

func TestOrderedCandidatePreparationRejectsNonSavedOrBusyAdmission(t *testing.T) {
	for _, fault := range []string{"samples", "duplicate", "position", "not-saved", "server", "connected", "starting", "command", "operation", "closing", "cancel-before-admission", "home-during-capture", "network-during-capture"} {
		t.Run(fault, func(t *testing.T) {
			a, q := orderedPreparationFixture(t, "wg")
			observe := func(ctx context.Context) (string, error) { return "physical", ctx.Err() }
			switch fault {
			case "samples":
				q.Samples = 49
			case "duplicate":
				q.CandidateIDs = append(q.CandidateIDs, q.CandidateIDs[0])
			case "position":
				q.Position = 2
			case "not-saved":
				a.profiles.Profiles[2].MultihopNodes = nil
			case "server":
				a.profiles.Profiles[2].MultihopExecution = "server"
			case "connected":
				a.state.Connected = true
			case "starting":
				a.state.Phase = "starting"
			case "command":
				a.cmd = &exec.Cmd{}
			case "operation":
				a.connectionContext = context.Background()
			case "closing":
				a.closing = true
			case "cancel-before-admission":
				viaEntryControlFor(a).seen[q.RequestID] = time.Now()
			case "home-during-capture":
				observe = func(ctx context.Context) (string, error) {
					a.mu.Lock()
					a.state.Jumbo = true
					a.mu.Unlock()
					return "physical", ctx.Err()
				}
			case "network-during-capture":
				calls := 0
				observe = func(ctx context.Context) (string, error) {
					calls++
					if calls == 1 {
						return "physical", ctx.Err()
					}
					return "replacement", ctx.Err()
				}
			}
			p, err := beginOrderedCandidatePreparationWithNetwork(context.Background(), a, q, observe)
			if err == nil || p != nil {
				if p != nil {
					_ = p.finish()
				}
				t.Fatal("invalid preparation admitted", fault)
			}
			if a.candidatePreparation != nil || viaEntryControlFor(a).owner != nil {
				t.Fatal("failed capture published temporary authority")
			}
			if !a.operationMu.TryLock() {
				t.Fatal("failed capture retained operation lock")
			}
			a.operationMu.Unlock()
		})
	}
}

func TestOrderedCandidatePreparationObservedChangesNeverRevive(t *testing.T) {
	for _, fault := range []string{"middle-source", "candidate-source", "selected", "home", "home-phase", "home-node", "network", "owner"} {
		t.Run(fault, func(t *testing.T) {
			a, q := orderedPreparationFixture(t, "wg")
			network := "physical"
			p, err := beginOrderedCandidatePreparationWithNetwork(context.Background(), a, q, func(ctx context.Context) (string, error) { return network, ctx.Err() })
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = p.finish() }()
			before := cloneRouterProfileStore(a.profiles)
			oldState := a.state
			switch fault {
			case "middle-source":
				a.profiles.Profiles[1].APIToken += "-changed"
			case "candidate-source":
				a.profiles.Profiles[3].External.Shadowsocks.Password = strings.Repeat("x", 44)
			case "selected":
				a.profiles.SelectedID = a.profiles.Profiles[0].ID
			case "home":
				a.state.DAITA = true
			case "home-phase":
				a.state.Phase = "starting"
			case "home-node":
				a.state.RouterID = "another-visible-node"
			case "network":
				network = "replacement"
			case "owner":
				a.candidatePreparation = &orderedCandidatePreparation{}
			}
			if p.sourceCurrent(context.Background()) == nil {
				t.Fatal("observed original capture loss was accepted")
			}
			a.profiles, a.state, a.candidatePreparation, network = before, oldState, p, "physical"
			if p.sourceCurrent(context.Background()) == nil || !p.invalidated.Load() || p.operation.Err() == nil {
				t.Fatal("away/back revived original preparation")
			}
		})
	}
}

func TestOrderedCandidatePreparationCancelJoinsWorkerBeforeLeaseAndDown(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		a, q := orderedPreparationFixture(t, "wg")
		p := beginOrderedPreparationFixture(t, a, q)
		bindOrderedPreparationFixture(t, p)
		if err := p.holdLease(context.Background()); err != nil {
			t.Fatal(err)
		}
		joined, err := p.beginWorker(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if err := cancelViaEntryOperationContext(context.Background(), a); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		err = cleanupViaEntryOwnerContext(ctx, p.control, p.owner)
		cancel()
		if err == nil || p.down || p.owner.drained || !mtuSuspended(a) || a.candidatePreparation != p || a.connectionContext != p.operation {
			t.Fatal("cancel released unjoined worker, lease or operation", err)
		}
		joined(nil)
		if err := p.finish(); err != nil {
			t.Fatal(err)
		}
		if !p.down || !p.owner.drained || mtuSuspended(a) || a.candidatePreparation != nil || a.connectionContext != nil {
			t.Fatal("joined worker did not retire original lease and purpose")
		}
	})
}

func TestOrderedCandidatePreparationRetainsExactNativeDrainForRetry(t *testing.T) {
	a, q := orderedPreparationFixture(t, "wg")
	p := beginOrderedPreparationFixture(t, a, q)
	launch := bindOrderedPreparationFixture(t, p)
	if err := p.holdLease(context.Background()); err != nil {
		t.Fatal(err)
	}
	joined, err := p.beginWorker(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	allow := false
	calls := 0
	retirement := &desktopNodeChainCandidateRetirement{launch: launch, request: "exact-original-child", run: func(ctx context.Context) error {
		calls++
		if !allow {
			return errors.New("original native worker remains")
		}
		return ctx.Err()
	}}
	launch.chain.candidatePending = retirement
	joined(&desktopNodeChainCandidatePendingError{retirement: retirement, cause: errors.New("cancel still draining")})
	if err := p.finish(); err == nil || p.owner.drained || p.down || calls != 1 || !mtuSuspended(a) || a.candidatePreparation != p {
		t.Fatal("failed child drain lost retained authority", err)
	}
	if guardViaEntryDecision(a) == nil {
		t.Fatal("replacement admitted while original child still owned")
	}
	allow = true
	if err := cleanupViaEntryOwnerContext(context.Background(), p.control, p.owner); err != nil {
		t.Fatal(err)
	}
	if calls != 2 || !retirement.joined.Load() || !p.owner.drained || !p.down || mtuSuspended(a) || a.candidatePreparation != nil {
		t.Fatal("retry did not join exact original child before DOWN")
	}
}

func TestOrderedCandidatePreparationLateCleanupPreservesReplacement(t *testing.T) {
	a, q := orderedPreparationFixture(t, "wg")
	p := beginOrderedPreparationFixture(t, a, q)
	bindOrderedPreparationFixture(t, p)
	replacement := &orderedCandidatePreparation{}
	operation, cancel := context.WithCancel(context.Background())
	defer cancel()
	command := &exec.Cmd{}
	a.candidatePreparation, a.connectionContext, a.connectionCancel, a.cmd = replacement, operation, cancel, command
	a.state = state{Connected: true, Phase: "connected", RouterID: "replacement", Mode: "replacement"}
	replacementState := a.state
	newOwner := &viaEntryOwner{id: strings.Repeat("d", 32), running: true}
	p.control.owner = newOwner
	if err := p.finish(); err != nil {
		t.Fatal(err)
	}
	if a.candidatePreparation != replacement || a.connectionContext != operation || a.cmd != command || a.state != replacementState || p.control.owner != newOwner || operation.Err() != nil {
		t.Fatal("late old cleanup changed replacement identity")
	}
}

func TestOrderedCandidatePreparationJoinedWorkerCannotOutliveRetirementLocks(t *testing.T) {
	for _, held := range []string{"lifecycle-after-join", "final-app-publication"} {
		t.Run(held, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				a, q := orderedPreparationFixture(t, "wg")
				p := beginOrderedPreparationFixture(t, a, q)
				bindOrderedPreparationFixture(t, p)
				if err := p.holdLease(context.Background()); err != nil {
					t.Fatal(err)
				}
				// This channel models only the worker's join boundary; no native
				// proof or successful child result is manufactured by this test.
				worker := make(chan struct{})
				p.workerDone = worker
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				finished := make(chan error, 1)
				go func() { finished <- cleanupViaEntryOwnerContext(ctx, p.control, p.owner) }()
				synctest.Wait() // retirement reached the original worker join
				if held == "lifecycle-after-join" {
					p.mu.Lock()
				} else {
					a.mu.Lock()
				}
				close(worker)
				err := <-finished
				if held == "lifecycle-after-join" {
					p.mu.Unlock()
				} else {
					a.mu.Unlock()
				}
				if !errors.Is(err, context.DeadlineExceeded) || p.down || p.owner.drained || p.releaseLease == nil || a.candidatePreparation != p || a.connectionContext != p.operation {
					t.Fatal("deadline lost cleanup authority after the worker joined", err)
				}
				if err := p.finish(); err != nil {
					t.Fatal(err)
				}
				if !p.down || !p.owner.drained || mtuSuspended(a) {
					t.Fatal("original cleanup could not retry after bounded lock refusal")
				}
			})
		})
	}
}

func TestOrderedCandidatePreparationDownRequiresStablePhaseAndNoNativeOwner(t *testing.T) {
	for _, fault := range []string{"stopping", "native-node", "native-graph", "public-graph", "relay"} {
		t.Run(fault, func(t *testing.T) {
			a, q := orderedPreparationFixture(t, "wg")
			p := beginOrderedPreparationFixture(t, a, q)
			bindOrderedPreparationFixture(t, p)
			if err := p.holdLease(context.Background()); err != nil {
				t.Fatal(err)
			}
			foreign := &desktopNodeLaunch{}
			switch fault {
			case "stopping":
				a.state.Phase = "stopping"
			case "native-node":
				desktopNodeOwners.Store(a, foreign)
			case "native-graph":
				nativeMultihopOwners.Store(a, &nativeMultihopRuntime{launch: foreign})
			case "public-graph":
				activeMultihopGraphs.Store(a, activeMultihopGraph{EntryID: "foreign-original"})
			case "relay":
				desktopRelays.Store(a, &desktopRelayOwner{})
			}
			if err := p.finish(); err == nil || p.down || p.owner.drained || !mtuSuspended(a) || a.candidatePreparation != p || a.connectionContext != p.operation {
				t.Fatal("unconfirmed DOWN discarded exact cleanup owner", err)
			}
			// This model's boundary is now explicitly retired; production may only
			// obtain the equivalent acknowledgement from that exact native owner.
			switch fault {
			case "stopping":
				a.state.Phase = "off"
			case "native-node":
				if v, ok := desktopNodeOwners.Load(a); !ok || v != foreign {
					t.Fatal("cleanup erased foreign native owner")
				}
				desktopNodeOwners.Delete(a)
			case "native-graph":
				if v, ok := nativeMultihopOwners.Load(a); !ok || v.(*nativeMultihopRuntime).launch != foreign {
					t.Fatal("cleanup erased foreign graph owner")
				}
				nativeMultihopOwners.Delete(a)
			case "public-graph":
				if _, ok := activeMultihopGraphs.Load(a); !ok {
					t.Fatal("cleanup erased foreign graph")
				}
				activeMultihopGraphs.Delete(a)
			case "relay":
				if _, ok := desktopRelays.Load(a); !ok {
					t.Fatal("cleanup erased foreign relay")
				}
				desktopRelays.Delete(a)
			}
			if err := cleanupViaEntryOwnerContext(context.Background(), p.control, p.owner); err != nil {
				t.Fatal(err)
			}
			if !p.down || !p.owner.drained || mtuSuspended(a) {
				t.Fatal("retired DOWN boundary could not complete original cleanup")
			}
		})
	}
}
