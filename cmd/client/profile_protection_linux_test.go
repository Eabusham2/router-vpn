//go:build linux

package main

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"router-vpn/internal/linuxprotection"
)

// A comparison-only retained-session model exercises public revisions and
// refusal paths. It has no native parent witness/baseline and cannot perform a
// successful removal. The installed-TUN gate separately proves actual Off.
func linuxProtectionModel(t *testing.T) (*app, *desktopLinuxNodeSession, *desktopLinuxNodeTransaction) {
	t.Helper()
	a := externalConnectionTestApp(t, "shadowsocks", false)
	profile := a.profiles.Profiles[3]
	controller := &ownedDesktopController{}
	parent := &desktopLinuxNodeParent{controller: controller, gate: make(chan struct{}, 1), ctx: context.Background()}
	parent.gate <- struct{}{}
	controller.nodeParent = parent
	a.localController = controller
	// This fixture models only the retained desktop-parent comparison path.
	// Its explicit service boundary reports no service-owned creator; it does
	// not replace the production native absent-service proof.
	client := &linuxStandardServiceProtectionClient{app: a, controller: controller}
	client.exchange = func(context.Context, linuxStandardServiceRequest) (*linuxStandardServiceProtectionData, error) {
		return &linuxStandardServiceProtectionData{AbsenceProved: true}, nil
	}
	linuxStandardServiceProtectionClients.Store(a, client)
	t.Cleanup(func() { linuxStandardServiceProtectionClients.Delete(a) })
	captured := &desktopLinuxNodeParentCapture{app: a, controller: controller, parent: parent, lifetime: parent.ctx}
	session := &desktopLinuxNodeSession{parent: captured, gate: make(chan struct{}, 1)}
	session.gate <- struct{}{}
	journal := &desktopLinuxNodeJournal{parent: captured}
	transaction := &desktopLinuxNodeTransaction{parent: captured, journal: journal, gate: make(chan struct{}, 1), profileID: profile.ID,
		selection: linuxprotection.NodeSelection{SessionID: strings.Repeat("1", 32), SourceSHA256: strings.Repeat("2", 64), Policy: "always"}}
	transaction.gate <- struct{}{}
	session.predecessor, session.journal, parent.session = transaction, journal, session
	parent.dependents = map[ownedDesktopNodeParent]struct{}{session: {}, journal: {}, transaction: {}}
	return a, session, transaction
}

func linuxProtectionPendingModel(t *testing.T) (*app, *desktopLinuxNodeSession, *desktopLinuxNodeProtectionOff) {
	t.Helper()
	a, session, transaction := linuxProtectionModel(t)
	profile := a.profiles.Profiles[3]
	result, err := profileProtectionOffResult(profile)
	if err != nil {
		t.Fatal(err)
	}
	captured := a.captureProfileProtection(profile)
	off := &desktopLinuxNodeProtectionOff{session: session, transaction: transaction, journal: session.journal,
		profileID: profile.ID, profileRevision: profileStartupSettingsToken(profile), resultRevision: profileStartupSettingsToken(result),
		requestID: strings.Repeat("3", 32), token: captured.token}
	session.off, transaction.off = off, off
	return a, session, off
}

func TestProfileProtectionLinuxRetainedOffRequiresActualNativeOwner(t *testing.T) {
	a, session, transaction := linuxProtectionModel(t)
	value := ownedProtectionGet(t, a)
	if value.ProtectionStatus != "retained" || value.EffectivePolicy != "always" || value.ProtectionProfileID != a.profiles.SelectedID {
		t.Fatal("Linux retained native policy was hidden behind its saved preference", value)
	}
	before := cloneRouterProfileStore(a.profiles)
	raw, err := os.ReadFile(a.cfg.ProfilesFile)
	if err != nil {
		t.Fatal(err)
	}
	response := postProtectionForTest(a, bytes.NewReader(ownedProtectionBody(t, value, "off")))
	if response.Code == http.StatusOK || !reflect.DeepEqual(before, a.profiles) || session.off != nil || transaction.off != nil || transaction.baselineReleased {
		t.Fatal("a comparison-only Linux source authorized native removal or saved Off", response.Code, response.Body.String())
	}
	after, err := os.ReadFile(a.cfg.ProfilesFile)
	if err != nil || !bytes.Equal(raw, after) {
		t.Fatal("refused native removal changed the actual private profile file", err)
	}
	request := httptest.NewRequest(http.MethodPost, "/api/profile/settings", strings.NewReader(`{"kill_switch_policy":"off"}`))
	response = httptest.NewRecorder()
	a.profileSettings(response, request)
	if response.Code != http.StatusConflict || !reflect.DeepEqual(before, a.profiles) {
		t.Fatal("broader settings bypassed retained Linux protection", response.Code, response.Body.String())
	}
}

func TestProfileProtectionLinuxBodyCannotReplaceRetainedOwner(t *testing.T) {
	for _, change := range []string{"source", "session", "controller", "journal", "profile", "selected", "active", "cancelled"} {
		t.Run(change, func(t *testing.T) {
			a, session, transaction := linuxProtectionModel(t)
			value := ownedProtectionGet(t, a)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			body := &startupSettingsMutationReader{Reader: bytes.NewReader(ownedProtectionBody(t, value, "off")), mutate: func() {
				switch change {
				case "source":
					// This comparison-only fixture has no live native transaction.
					// Recreate its populated fields without copying atomic ownership.
					replacement := &desktopLinuxNodeTransaction{
						parent: transaction.parent, journal: transaction.journal,
						gate: transaction.gate, profileID: transaction.profileID,
						selection: transaction.selection,
					}
					replacement.stopRequested.Store(transaction.stopRequested.Load())
					if !reflect.DeepEqual(transaction, replacement) {
						t.Fatal("source substitution fixture changed its inert transaction state")
					}
					session.predecessor = replacement
				case "session":
					copy := *session
					session.parent.parent.session = &copy
				case "controller":
					a.localController = &ownedDesktopController{}
				case "journal":
					session.journal = &desktopLinuxNodeJournal{}
				case "profile":
					a.profiles.Profiles[3].External.Shadowsocks.Password = "replacement-private-value"
				case "selected":
					a.profiles.SelectedID = "entry"
				case "active":
					a.cmd = &exec.Cmd{}
				case "cancelled":
					cancel()
				}
			}}
			response := httptest.NewRecorder()
			a.profileProtectionSettings(response, httptest.NewRequest(http.MethodPost, "/api/profile/protection", body).WithContext(ctx))
			if response.Code == http.StatusOK || transaction.off != nil || transaction.baselineReleased || a.profiles.Profiles[3].KillSwitchPolicy != "always" {
				t.Fatal("a changed application/source/request adopted Linux Off", response.Code, response.Body.String())
			}
		})
	}
}

func TestProfileProtectionLinuxPendingKeepsTruthfulStableRetry(t *testing.T) {
	a, session, off := linuxProtectionPendingModel(t)
	before := cloneRouterProfileStore(a.profiles)
	value := ownedProtectionGet(t, a)
	if value.ProtectionStatus != "off-pending" || value.EffectivePolicy != "unknown" || value.ProfileToken != off.token {
		t.Fatal("pending native outcome pretended Linux Off completed", value)
	}
	off.transaction.baselineReleased, off.absenceProved = true, true
	value = ownedProtectionGet(t, a)
	if value.ProtectionStatus != "off-unsaved" || value.EffectivePolicy != "off" || value.KillSwitchPolicy != "always" || value.ProfileToken != off.token {
		t.Fatal("release-but-unsaved did not retain its same explicit retry", value)
	}
	request := httptest.NewRequest(http.MethodPost, "/api/profile/settings", strings.NewReader(`{"kill_switch_policy":"off"}`))
	for _, internal := range []bool{false, true} {
		r := request
		if internal {
			r = withInternalMutationContext(r)
		}
		if release, err := a.beginMutationOperation(r); err == nil {
			release()
			t.Fatal("pending Linux Off admitted another profile mutation")
		}
	}
	if release, err := a.beginNodeBoundOperation(); err == nil {
		release()
		t.Fatal("pending Linux Off admitted node work")
	}
	if _, release, err := a.beginConnectionTransaction(); err == nil {
		release()
		t.Fatal("pending Linux Off admitted a replacement connection")
	}
	response := postProtectionForTest(a, bytes.NewReader(ownedProtectionBody(t, value, "on-connect")))
	if response.Code != http.StatusConflict || !reflect.DeepEqual(before, a.profiles) || session.off != off {
		t.Fatal("pending Linux Off changed into another preference operation")
	}
	result, err := profileProtectionOffResult(a.profiles.Profiles[3])
	if err != nil {
		t.Fatal(err)
	}
	a.profiles.Profiles[3], off.profileWritten = result, true
	value = ownedProtectionGet(t, a)
	if value.KillSwitchPolicy != "off" || value.ProfileToken != off.token || value.ProtectionStatus != "off-unsaved" {
		t.Fatal("published but unverified Off lost the accepted request token", value)
	}
	off.profileSaved = true
	value = ownedProtectionGet(t, a)
	if value.ProtectionStatus != "off-pending" || value.ProfileToken != off.token {
		t.Fatal("saved Off discarded unfinished native cleanup")
	}
}

func TestProfileProtectionLinuxExactPrivateStoreReadback(t *testing.T) {
	for _, fault := range []string{"none", "cancelled", "unwritten", "path", "selected", "credentials", "result", "policy", "truncated", "symlink"} {
		t.Run(fault, func(t *testing.T) {
			a := externalConnectionTestApp(t, "shadowsocks", false)
			result, err := profileProtectionOffResult(a.profiles.Profiles[3])
			if err != nil {
				t.Fatal(err)
			}
			a.profiles.Profiles[3] = result
			if err := a.persistProfilesLocked(); err != nil {
				t.Fatal(err)
			}
			off := &desktopLinuxNodeProtectionOff{profileID: result.ID, resultRevision: profileStartupSettingsToken(result), savedPath: a.cfg.ProfilesFile, profileWritten: true}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch fault {
			case "cancelled":
				cancel()
			case "unwritten":
				off.profileWritten = false
			case "path":
				off.savedPath = filepath.Join(t.TempDir(), "foreign.json")
			case "selected":
				a.profiles.SelectedID = "entry"
			case "credentials":
				a.profiles.Profiles[0].APIToken = "another-private-node"
			case "result":
				off.resultRevision = strings.Repeat("a", 64)
			case "policy":
				a.profiles.Profiles[3].KillSwitchPolicy, a.profiles.Profiles[3].KillSwitch = "always", true
			case "truncated":
				if err := os.WriteFile(off.savedPath, []byte("{"), 0600); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				original := off.savedPath + ".original"
				if err := os.Rename(off.savedPath, original); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(original, off.savedPath); err != nil {
					t.Fatal(err)
				}
			}
			a.mu.Lock()
			err = off.verifyProfileLocked(ctx, a)
			a.mu.Unlock()
			if (err == nil) != (fault == "none") || off.profileSaved != (fault == "none") {
				t.Fatal("private Off readback accepted changed/incomplete source or rejected exact published bytes", fault, err)
			}
			if fault != "none" && !errors.Is(err, errDesktopProtectionOffUnsaved) {
				t.Fatal("readback failure lost explicit unsaved state", err)
			}
		})
	}
}

func TestProfileProtectionLinuxJournalRequiresAcceptedOff(t *testing.T) {
	transaction := &desktopLinuxNodeTransaction{}
	intent := linuxprotection.JournalRecord{Phase: "intent", Intent: &linuxprotection.JournalIntent{Action: "off", RequestID: strings.Repeat("1", 32)}}
	if transaction.checkProtectionOffIntent(context.Background(), intent) == nil || transaction.checkProtectionOffSettlement(context.Background(), linuxprotection.JournalRecord{Phase: "settled"}) == nil {
		t.Fatal("Linux journal text manufactured an accepted saved-profile removal")
	}
	a, session, off := linuxProtectionPendingModel(t)
	_ = a
	other := &desktopLinuxNodeTransaction{off: off}
	if other.checkProtectionOffIntent(context.Background(), intent) == nil || other.checkProtectionOffSettlement(context.Background(), linuxprotection.JournalRecord{Phase: "settled"}) == nil {
		t.Fatal("another original transaction borrowed accepted Linux Off")
	}
	if session.off != off || off.transaction.off != off {
		t.Fatal("rejected journal mutation replaced the original owner")
	}
}
