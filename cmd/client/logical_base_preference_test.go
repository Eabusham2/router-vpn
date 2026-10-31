package main

import (
	"bytes"
	"context"
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
	"testing/synctest"
	"time"

	"router-vpn/internal/common"
)

func logicalBasePublicFixture(t *testing.T, policy string) *desktopNodeConnectionFixture {
	t.Helper()
	f := newDesktopNodeConnectionFixture(t, policy, "")
	f.a.cfg.ModesFile = filepath.Join("..", "..", "configs", "client", "modes.json")
	f.a.profiles.Profiles[0].BaseTunnel = "auto"
	if err := f.a.persistProfiles(); err != nil {
		t.Fatal(err)
	}
	return f
}

func logicalBaseStored(t *testing.T, a *app) string {
	t.Helper()
	raw, err := os.ReadFile(a.cfg.ProfilesFile)
	var store common.RouterProfileStore
	if err != nil || json.Unmarshal(raw, &store) != nil || len(store.Profiles) != 1 {
		t.Fatal("could not inspect the actual saved logical preference", err)
	}
	return store.Profiles[0].BaseTunnel
}

func TestDesktopNodePublicLogicalBasePreferenceRetainsCapturedSource(t *testing.T) {
	for _, policy := range []string{"always", "on-connect"} {
		for _, test := range []struct{ name, mode, base, runtime, saved string }{
			{"wg", "base-raw", "wireguard", "wg", "wg"},
			{"awg", "base-raw", "awg", "awg2-fast", "awg"},
			{"proxy", "hysteria2", "wg", "hysteria2", "wg"},
			{"fallback", "base-raw", "wg", "awg2-fast", "wg"},
		} {
			t.Run(policy+"/"+test.name, func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					f := logicalBasePublicFixture(t, policy)
					if test.name == "fallback" {
						f.failedMode["wg"] = true
					}
					response := httptest.NewRecorder()
					f.a.connectLogical(response, httptest.NewRequest(http.MethodPost, "/api/connect-logical",
						strings.NewReader(`{"mode":"`+test.mode+`","base":"`+test.base+`"}`)))
					if response.Code != http.StatusOK || !f.a.state.Connected || f.a.state.RuntimeMode != test.runtime || len(f.children) == 0 {
						t.Fatal("logical preference did not retain its actual proved public path", response.Code, response.Body.String())
					}
					child := f.children[len(f.children)-1]
					profile, err := f.a.activeProfile()
					if err != nil || profile.BaseTunnel != test.saved || logicalBaseStored(t, f.a) != test.saved ||
						child.launch.ownedNode.profileToken != desktopOwnedNodeProfileToken(profile) ||
						validateDesktopOwnedNodeSourceProfile(profile, child.launch.endpoint, string(child.launch.ownedNode.source)) != nil {
						t.Fatal("logical preference changed the complete profile after native graph capture", err)
					}
					// The production tracker observes the newly returned logical
					// state on its normal 100 ms cadence before measurements adopt it.
					time.Sleep(200 * time.Millisecond)
					if _, _, err := captureSpeedLabIdentity(f.a); err != nil {
						t.Fatal("logical preference invalidated the proved measurement identity", err)
					}
					time.Sleep(2 * time.Second)
					if _, err := f.a.readDesktopOwnedNodeReady(child.launch, false); err != nil || child.Alive() != nil || !f.a.state.Connected {
						t.Fatal("logical preference retired the captured runtime after the HTTP response", err)
					}
				})
			})
		}
	}
}

func TestDesktopNodePublicLogicalBasePreferencePreparationFailureRollsBack(t *testing.T) {
	for _, fault := range []string{"verify", "cancel", "save"} {
		t.Run(fault, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f := logicalBasePublicFixture(t, "always")
				path := f.a.cfg.ProfilesFile
				before, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				f.a.nodeConnectionHost.verify = func(ctx context.Context, _ string) (string, error) {
					if fault == "cancel" {
						f.a.cancelConnectionOperation()
						return "", ctx.Err()
					}
					return "", errors.New("captured package fixture rejected preparation")
				}
				if fault == "save" {
					blocker := filepath.Join(t.TempDir(), "not-a-directory")
					if err := os.WriteFile(blocker, []byte("owned fixture"), 0600); err != nil {
						t.Fatal(err)
					}
					f.a.cfg.ProfilesFile = filepath.Join(blocker, "routers.json")
				}
				response := httptest.NewRecorder()
				f.a.connectLogical(response, httptest.NewRequest(http.MethodPost, "/api/connect-logical", strings.NewReader(`{"mode":"base-raw","base":"awg"}`)))
				after, readErr := os.ReadFile(path)
				if response.Code < http.StatusBadRequest || f.a.profiles.Profiles[0].BaseTunnel != "auto" ||
					readErr != nil || !bytes.Equal(before, after) || len(f.children) != 0 || f.kernel.target != nil || f.a.nodeProtection.generation != 0 {
					t.Fatal("failed logical preparation changed the original preference or native owner", response.Code, response.Body.String(), readErr)
				}
			})
		})
	}
}

func TestDesktopNodePublicLogicalBasePreferenceFailedSuccessorKeepsMatchingSource(t *testing.T) {
	for _, policy := range []string{"always", "on-connect"} {
		t.Run(policy, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f := logicalBasePublicFixture(t, policy)
				f.failedMode["wg"], f.failedMode["awg2-fast"] = true, true
				response := httptest.NewRecorder()
				f.a.connectLogical(response, httptest.NewRequest(http.MethodPost, "/api/connect-logical", strings.NewReader(`{"mode":"base-raw","base":"awg"}`)))
				if response.Code != http.StatusServiceUnavailable || f.a.state.Connected || len(f.children) != 2 {
					t.Fatal("logical failure did not execute and join its actual candidate paths", response.Code, response.Body.String())
				}
				for _, child := range f.children {
					if child.Alive() == nil {
						t.Fatal("logical failure retained a live candidate")
					}
				}
				want := "auto"
				if policy == "always" {
					want = "awg"
					profile, _ := f.a.activeProfile()
					if f.a.nodeProtection.target == nil || f.a.nodeProtection.profileRevision != desktopOwnedNodeProfileToken(profile) ||
						!strings.Contains(response.Body.String(), "retained connection owner") {
						t.Fatal("logical failure relabeled its retained successor or hid the retained preference")
					}
				} else if f.kernel.target != nil || f.a.nodeProtection != nil && !f.a.nodeProtection.provedEmpty() {
					t.Fatal("on-connect failure did not prove joined absence")
				}
				if f.a.profiles.Profiles[0].BaseTunnel != want || logicalBaseStored(t, f.a) != want {
					t.Fatal("logical failure saved a preference inconsistent with its retained source")
				}
			})
		})
	}
}

func logicalBaseTransactionFixture(t *testing.T) (*app, context.Context, context.CancelFunc) {
	t.Helper()
	profile, _ := desktopNodeFixture(t, "198.51.100.8")
	profile.BaseTunnel = "wg"
	ctx, cancel := context.WithCancel(context.Background())
	a := &app{cfg: common.ClientConfig{ProfilesFile: filepath.Join(t.TempDir(), "routers.json")},
		profiles: common.RouterProfileStore{SelectedID: profile.ID, Profiles: []common.RouterProfile{profile}},
		state:    state{Phase: "requested"}, connectionContext: ctx}
	a.operationMu.Lock()
	t.Cleanup(func() { desktopNodeOwners.Delete(a); cancel(); a.operationMu.Unlock() })
	if err := a.persistProfiles(); err != nil {
		t.Fatal(err)
	}
	return a, ctx, cancel
}

func TestLogicalBaseRollbackRejectsChangedOrUnjoinedOwners(t *testing.T) {
	for _, fault := range []string{"operation", "selection", "profile", "command", "workspace", "new-unknown-slot", "replaced-slot", "lost-slot", "active", "retiring", "off", "journal-close", "new-target", "revision"} {
		t.Run(fault, func(t *testing.T) {
			a, ctx, _ := logicalBaseTransactionFixture(t)
			target := desktopNodeProtectionInstalled(desktopNodeProtectionPolicy(t, "1", "always", 0))
			slot := &desktopNodeProtectionSlot{known: true, target: &target, generation: 4,
				binding: desktopNodeProtectionBinding{ProfileID: a.profiles.SelectedID, SourceSHA256: target.Capture.SourceSHA256}, profileRevision: strings.Repeat("a", 64)}
			if fault != "new-unknown-slot" {
				a.nodeProtection = slot
			}
			capture, err := a.stageLogicalBasePreference(ctx, "awg")
			if err != nil {
				t.Fatal(err)
			}
			switch fault {
			case "operation":
				a.connectionContext = context.Background()
			case "selection":
				a.profiles.SelectedID = "replacement"
			case "profile":
				a.profiles.Profiles[0].APIToken = "replacement-private-token"
			case "command":
				a.cmd = &exec.Cmd{}
			case "workspace":
				desktopNodeOwners.Store(a, &desktopNodeLaunch{})
			case "new-unknown-slot":
				a.nodeProtection = &desktopNodeProtectionSlot{}
			case "replaced-slot":
				a.nodeProtection = &desktopNodeProtectionSlot{known: true}
			case "lost-slot":
				a.nodeProtection = nil
			case "active":
				slot.active = &desktopNodeProtectionAttempt{}
			case "retiring":
				slot.retirement = &desktopNodeProtectionFixtureRelease{}
			case "off":
				slot.off = &desktopNodeProtectionOff{}
			case "journal-close":
				slot.journalClosing = true
			case "new-target":
				changed := *slot.target
				changed.Capture.SessionID = strings.Repeat("2", 32)
				slot.target = &changed
			case "revision":
				slot.profileRevision = strings.Repeat("b", 64)
			}
			if err := a.rollbackLogicalBasePreference(capture); err == nil || a.profiles.Profiles[0].BaseTunnel != "awg" || logicalBaseStored(t, a) != "awg" {
				t.Fatal("logical rollback replaced another captured owner or source", fault, err)
			}
		})
	}
}

func TestLogicalBaseRollbackPreservesDurablePredecessorAndCancellation(t *testing.T) {
	a, ctx, cancel := logicalBaseTransactionFixture(t)
	slot, attempt, kernel, journal, process := desktopNodeJournalFixture(t, true)
	target := *kernel.target
	if err := slot.provePrepared(context.Background(), attempt, target, func() bool { return true }); err != nil {
		t.Fatal(err)
	}
	if err := slot.finish(context.Background(), attempt, desktopNodeProtectionRetired(attempt, &target), func(context.Context) error {
		process.closed, kernel.locked = true, false
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	a.nodeProtection = slot
	before, err := journal.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	beforeRevision, beforeBinding := slot.profileRevision, slot.binding
	capture, err := a.stageLogicalBasePreference(ctx, "awg")
	if err != nil {
		t.Fatal(err)
	}
	// A failed unadopted attempt may advance generation, but the exact joined
	// predecessor and its durable source revision remain the only authority.
	slot.generation++
	cancel()
	if err := a.rollbackLogicalBasePreference(capture); err != nil {
		t.Fatal("cancelled original operation could not restore its untouched preference", err)
	}
	after, err := journal.Snapshot(context.Background())
	if err != nil || !reflect.DeepEqual(before, after) || slot.profileRevision != beforeRevision || slot.binding != beforeBinding ||
		slot.target == nil || *slot.target != target || a.profiles.Profiles[0].BaseTunnel != "wg" || logicalBaseStored(t, a) != "wg" {
		t.Fatal("logical rollback changed the durable predecessor or failed to restore preference", err)
	}
}

func TestLogicalBaseRollbackWriteFailureRetainsSavedStagedValue(t *testing.T) {
	a, ctx, _ := logicalBaseTransactionFixture(t)
	capture, err := a.stageLogicalBasePreference(ctx, "awg")
	if err != nil {
		t.Fatal(err)
	}
	savedPath := a.cfg.ProfilesFile
	blocker := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(blocker, []byte("owned fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	a.cfg.ProfilesFile = filepath.Join(blocker, "routers.json")
	if err := a.rollbackLogicalBasePreference(capture); err == nil || a.profiles.Profiles[0].BaseTunnel != "awg" {
		t.Fatal("failed logical rollback diverged from the durably staged preference", err)
	}
	a.cfg.ProfilesFile = savedPath
	if logicalBaseStored(t, a) != "awg" {
		t.Fatal("failed rollback changed the saved staged preference")
	}
}
