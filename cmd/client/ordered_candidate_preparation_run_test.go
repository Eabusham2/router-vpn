package main

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"router-vpn/internal/mobiletor"
)

func TestOrderedCandidatePreparedObservationCannotAdoptSourceOnlyInventory(t *testing.T) {
	a, q := orderedPreparationFixture(t, "wg")
	p := beginOrderedPreparationFixture(t, a, q)
	launch := bindOrderedPreparationFixture(t, p)
	r := &orderedCandidatePreparedRuntime{preparation: p, catalog: p.inventory}
	if r.pulseCurrent(context.Background()) == nil || !p.invalidated.Load() {
		t.Fatal("source-only inventory fabricated a temporary native observation")
	}
	if p.inventory.current(context.Background()) == nil || a.state.Connected || launch.chain.ready != nil {
		t.Fatal("temporary observation loosened connected or native proof authority")
	}
	if _, err := exchangeDesktopNodeChainCandidateObserved(context.Background(), p.inventory, q.CandidateIDs[0], nil, nil); err == nil {
		t.Fatal("child exchange accepted missing retained observations")
	}
	if launch.directory != "" || launch.command != nil {
		t.Fatal("rejected observation created native side effects")
	}
}

func TestOrderedCandidatePreparedInventoryKeepsOriginalSources(t *testing.T) {
	a, q := orderedPreparationFixture(t, "wg")
	p := beginOrderedPreparationFixture(t, a, q)
	launch, err := newDesktopNodeChainLaunch(p.selection, strings.Repeat("c", 32), "windows")
	if err != nil {
		t.Fatal(err)
	}
	current, err := captureDesktopNodeChainCandidateSources(context.Background(), a, launch, q.Position, q.CandidateIDs)
	if err != nil || !orderedCandidateSameInventory(p.inventory, current) {
		t.Fatal("fresh native session changed identical original source inventory", err)
	}
	for _, fault := range []string{"revision", "inventory", "profile", "assets", "files"} {
		t.Run(fault, func(t *testing.T) {
			copy := *current
			switch fault {
			case "revision":
				copy.revision += "replacement"
			case "inventory":
				copy.inventory += " "
			case "profile":
				copy.profiles = map[string]string{q.CandidateIDs[0]: "replacement"}
			case "assets":
				copy.assets = append(copy.assets[:len(copy.assets):len(copy.assets)], viaEntryAsset{id: "replacement"})
			case "files":
				copy.files = append(copy.files[:len(copy.files):len(copy.files)], desktopCandidateSourceFile{path: "replacement"})
			}
			if orderedCandidateSameInventory(p.inventory, &copy) {
				t.Fatal("runtime adopted replacement original sources", fault)
			}
		})
	}
}

// These fixtures model the boundary AFTER native retirement, so they exercise
// only captured workspace/publication cleanup. They never invoke a platform
// native launch, issue a ready record or claim a routed proof.
func orderedCandidateWindowsDownFixture(t *testing.T) (*orderedCandidatePreparation, *desktopNodeLaunch) {
	t.Helper()
	a, q := orderedPreparationFixture(t, "wg")
	p := beginOrderedPreparationFixture(t, a, q)
	launch := bindOrderedPreparationFixture(t, p)
	launch.ownedNode = &desktopOwnedNodeRuntime{chain: launch.chain, retired: true, operation: p.operation}
	launch.command = &exec.Cmd{}
	directory := filepath.Join(t.TempDir(), "captured-workspace")
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	if err := captureDesktopRuntimeDirectory(launch, directory); err != nil {
		t.Fatal(err)
	}
	if err := writeDesktopRuntimeFile(launch, "sing-box.json", []byte("{}"), false); err != nil {
		t.Fatal(err)
	}
	a.cmd = launch.command
	a.state.Mode, a.state.Phase = "multihop", "candidate:testing"
	desktopNodeOwners.Store(a, launch)
	t.Cleanup(func() {
		desktopNodeOwners.Delete(a)
		a.cmd, a.state = nil, p.state
		launch.ownedNode.retired = true
	})
	return p, launch
}

func TestOrderedCandidateWindowsDownRetainsExactRetirement(t *testing.T) {
	for _, fault := range []string{"original", "unjoined", "foreign-purpose", "replacement-command", "replacement-owner"} {
		t.Run(fault, func(t *testing.T) {
			p, launch := orderedCandidateWindowsDownFixture(t)
			a := p.app
			before := cloneRouterProfileStore(a.profiles)
			replacementCommand, replacementOwner := &exec.Cmd{}, &desktopNodeLaunch{}
			switch fault {
			case "unjoined":
				launch.ownedNode.retired = false
			case "foreign-purpose":
				launch.chain.preparation = &orderedCandidatePreparation{}
				defer func() { launch.chain.preparation = p }()
			case "replacement-command":
				a.cmd = replacementCommand
				a.connectionContext = context.Background()
			case "replacement-owner":
				desktopNodeOwners.Store(a, replacementOwner)
			}
			err := p.finishWindowsNativeDown(context.Background(), launch)
			if fault == "unjoined" || fault == "foreign-purpose" {
				if err == nil || p.workspaceDown || a.cmd != launch.command {
					t.Fatal("unproved/foreign retirement erased the original runtime", err)
				}
				if _, err := os.Stat(launch.directory); err != nil {
					t.Fatal("refused retirement removed workspace", err)
				}
				return
			}
			if err != nil || !p.workspaceDown {
				t.Fatal("joined exact retirement failed its workspace boundary", err)
			}
			if _, err := os.Stat(launch.directory); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("joined original workspace remains", err)
			}
			if fault == "replacement-command" {
				if a.cmd != replacementCommand || a.state.Phase != "candidate:testing" {
					t.Fatal("captured retirement replaced another command or Home state")
				}
			} else if a.cmd != nil || a.state != p.state {
				t.Fatal("original Home did not return to its exact disconnected capture")
			}
			if fault == "replacement-owner" {
				if got, _ := desktopNodeOwners.Load(a); got != replacementOwner || orderedCandidatePreparationDownLocked(a) {
					t.Fatal("retirement cleared/accepted a replacement registry")
				}
			}
			if !reflect.DeepEqual(before, a.profiles) {
				t.Fatal("native DOWN changed saved history or preferences")
			}
		})
	}
}

func TestOrderedCandidateWindowsDownRetryRetainsWorkspaceCompletion(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p, launch := orderedCandidateWindowsDownFixture(t)
		p.app.mu.Lock()
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		err := p.finishWindowsNativeDown(ctx, launch)
		cancel()
		if !errors.Is(err, context.DeadlineExceeded) || !p.workspaceDown || p.app.cmd != launch.command {
			p.app.mu.Unlock()
			t.Fatal("bounded publication lost its original completed workspace", err)
		}
		p.app.mu.Unlock()
		if err := p.finishWindowsNativeDown(context.Background(), launch); err != nil || p.app.cmd != nil {
			t.Fatal("retry rediscovered a deleted workspace instead of original completion", err)
		}
	})
}

func TestOrderedCandidateNativeDownRetainsReviewReservation(t *testing.T) {
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
	joined(nil)
	if err := p.retireNative(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !p.nativeDown || p.down || p.owner.drained || mtuSuspended(a) || a.candidatePreparation != p || a.connectionContext != nil || !orderedCandidatePreparationDownLocked(a) {
		t.Fatal("native DOWN either kept native work/lease or released the separate review reservation")
	}
	if guardViaEntryDecision(a) == nil {
		t.Fatal("native DOWN silently admitted replacement before observer/review cleanup")
	}
	if err := p.finish(); err != nil || !p.down || !p.owner.drained || a.candidatePreparation != nil {
		t.Fatal("full cleanup did not retire the separate review reservation", err)
	}
}

func TestOrderedCandidatePreparedReaderCannotAdoptReplacement(t *testing.T) {
	original := desktopNodeMTURecord{Session: "session", Config: "config", Path: "path", Reader: 7, Interface: "tun", Index: 12, MTU: 1280, NetworkReceipt: "native-receipt"}
	for _, fault := range []string{"heartbeat", "session", "config", "path", "reader", "interface", "index", "mtu", "receipt", "active", "failure"} {
		t.Run(fault, func(t *testing.T) {
			current := original
			switch fault {
			case "heartbeat":
				current.Heartbeat++
			case "session":
				current.Session += "replacement"
			case "config":
				current.Config += "replacement"
			case "path":
				current.Path += "replacement"
			case "reader":
				current.Reader++
			case "interface":
				current.Interface += "replacement"
			case "index":
				current.Index++
			case "mtu":
				current.MTU++
			case "receipt":
				current.NetworkReceipt += "replacement"
			case "active":
				current.Active = true
			case "failure":
				current.Failure = "failed"
			}
			if orderedCandidateSameReader(original, current) != (fault == "heartbeat") {
				t.Fatal("temporary measurement adopted a replacement native reader", fault)
			}
		})
	}
}

func TestOrderedCandidateWindowsProtectionRetiresOnlyOriginalSuccessor(t *testing.T) {
	for _, fault := range []string{"on-connect", "always", "predecessor", "source", "session", "baseline", "policy", "pending-release", "retry", "retry-generation", "retry-target", "retry-owner"} {
		t.Run(fault, func(t *testing.T) {
			a, q := orderedPreparationFixture(t, "wg")
			if fault == "always" {
				for i := range a.profiles.Profiles {
					a.profiles.Profiles[i].KillSwitchPolicy = "always"
				}
			}
			p := beginOrderedPreparationFixture(t, a, q)
			launch := bindOrderedPreparationFixture(t, p)
			launch.ownedNode = &desktopOwnedNodeRuntime{chain: launch.chain, profileToken: desktopOwnedNodeProfileToken(p.selection.Control)}
			kernel := &desktopNodeProtectionFixture{}
			slot := &desktopNodeProtectionSlot{backend: kernel.backend()}
			if fault == "predecessor" {
				previous := desktopNodeProtectionInstalled(desktopNodeProtectionPolicy(t, "d", "on-connect", 0))
				kernel.target, slot.target, slot.known = &previous, copyDesktopNodeProtectionTarget(&previous), true
			}
			attempt, err := slot.beginNodeChain(context.Background(), launch, launch.chain.policy)
			if err != nil {
				t.Fatal(err)
			}
			launch.ownedNode.slot, launch.ownedNode.attempt = slot, attempt
			meta := launch.chain.policy.Metadata()
			target := mobiletor.DesktopWindowsProtectionTarget{Capture: mobiletor.DesktopSocketCapture{SessionID: meta.SessionID, SourceSHA256: meta.SourceSHA256, NetworkID: strings.Repeat("d", 32)}, Policy: meta.KillSwitchPolicy, BaselineSHA256: strings.Repeat("e", 64)}
			if fault != "predecessor" {
				kernel.target, kernel.locked = copyDesktopNodeProtectionTarget(&target), true
				if err := slot.provePrepared(context.Background(), attempt, target, func() bool { return true }); err != nil {
					t.Fatal(err)
				}
			}
			if err := slot.finish(context.Background(), attempt, desktopNodeProtectionRetired(attempt, kernel.target), func(context.Context) error { kernel.locked = false; return nil }); err != nil {
				t.Fatal(err)
			}
			launch.ownedNode.retired = true
			// The real slot state machine runs against its existing comparison
			// backend; these tests do not attest native Windows policy.
			switch fault {
			case "source":
				slot.target.Capture.SourceSHA256 = strings.Repeat("f", 64)
			case "session":
				slot.target.Capture.SessionID = strings.Repeat("f", 32)
			case "baseline":
				slot.target.BaselineSHA256 = strings.Repeat("f", 64)
			case "policy":
				slot.target.Policy = "always"
			case "pending-release":
				slot.retirement = &desktopNodeProtectionFixtureRelease{}
			}
			if strings.HasPrefix(fault, "retry") {
				kernel.closeFail = true
				if err := p.releaseWindowsProtection(context.Background(), launch); err == nil || p.windowsRelease == nil || p.windowsRelease.done || slot.retirement == nil {
					t.Fatal("failed original release lost its retained exact retry", err)
				}
				kernel.closeFail = false
				switch fault {
				case "retry-generation":
					slot.generation++
				case "retry-target":
					slot.target.Capture.SessionID = strings.Repeat("f", 32)
				case "retry-owner":
					slot.retirement = &desktopNodeProtectionFixtureRelease{}
				}
			}
			err = p.releaseWindowsProtection(context.Background(), launch)
			valid := fault == "on-connect" || fault == "always" || fault == "predecessor" || fault == "retry"
			if (err == nil) != valid {
				t.Fatal("candidate release changed original successor authority", fault, err)
			}
			if !valid {
				if strings.HasPrefix(fault, "retry") {
					if kernel.releases != 1 || kernel.closes != 1 {
						t.Fatal("replaced retry touched native backend")
					}
				} else if kernel.releases != 0 {
					t.Fatal("foreign target reached native release")
				}
			} else if fault == "on-connect" || fault == "retry" {
				if kernel.target != nil || slot.target != nil || !p.windowsRelease.done {
					t.Fatal("original on-connect successor was not released")
				}
			} else if kernel.target == nil || slot.target == nil || (fault == "predecessor" && kernel.releases != 0) {
				t.Fatal("disconnect released Always or the unchanged predecessor")
			}
			// Keep the fixture's synthetic native fields out of the foundation
			// cleanup: the model owns no real child, baseline or workspace.
			launch.ownedNode = nil
		})
	}
}
