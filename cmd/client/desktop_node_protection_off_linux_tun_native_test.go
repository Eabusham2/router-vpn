//go:build linux && routervpn_controller_privileged

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"time"

	"router-vpn/internal/common"
	"router-vpn/internal/linuxprotection"
	"router-vpn/internal/mobiletor"
)

type linuxHostTUNOffResult struct {
	RetainedAlways      bool `json:"retained_always"`
	NetworkReleased     bool `json:"network_released"`
	ProfileSaved        bool `json:"profile_saved"`
	JournalSettled      bool `json:"journal_settled"`
	ReplacementRejected bool `json:"replacement_rejected"`
	ReplayRejected      bool `json:"replay_rejected"`
	SaveRetried         bool `json:"save_retried"`
}

// The private peer exposes a distinct ordinary physical response. This probe
// belongs to the installed controller, with no native socket grant or TUN
// binding. It must be blocked by disconnected Always and work only after Off.
func linuxHostTUNOffNetwork(ctx context.Context, allowed bool) error {
	probe, cancel := context.WithTimeout(ctx, 750*time.Millisecond)
	defer cancel()
	transport := &http.Transport{Proxy: nil, DialContext: (&net.Dialer{}).DialContext, DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("unexpected private peer redirect") }}
	request, err := http.NewRequestWithContext(probe, http.MethodGet, "http://10.77.0.1:8787/health", nil)
	if err != nil {
		return err
	}
	response, err := client.Do(request)
	if !allowed {
		if response != nil {
			response.Body.Close()
		}
		if err == nil {
			return errors.New("ordinary physical traffic bypassed retained Always protection")
		}
		return nil
	}
	if err != nil {
		return errors.Join(err, errors.New("explicit Off did not restore ordinary physical traffic"))
	}
	body, readErr := io.ReadAll(io.LimitReader(response.Body, 4097))
	closeErr := response.Body.Close()
	if readErr != nil || closeErr != nil || response.StatusCode != http.StatusOK || len(body) > 4096 || validateCapturedNodeProof(linuxHostTUNNodeID, body) != nil {
		return errors.Join(readErr, closeErr, errors.New("released ordinary traffic did not reach the independent private peer"))
	}
	return nil
}

func linuxHostTUNOffSettings(ctx context.Context, a *app) (profileProtectionSettings, error) {
	response := httptest.NewRecorder()
	a.profileProtectionSettings(response, httptest.NewRequest(http.MethodGet, "/api/profile/protection", nil).WithContext(ctx))
	var value profileProtectionSettings
	if response.Code != http.StatusOK || decodeRelayControlJSON(response.Body.Bytes(), &value) != nil || len(value.ProfileToken) != 64 {
		return value, fmt.Errorf("installed Linux protection GET failed: %d %s", response.Code, response.Body.String())
	}
	return value, nil
}

func linuxHostTUNOffBody(value profileProtectionSettings) []byte {
	body, _ := json.Marshal(map[string]string{"profile_id": value.ProfileID, "profile_token": value.ProfileToken, "kill_switch_policy": "off"})
	return body
}

// Uses the public handler after the actual public Connect and Disconnect. All
// native baselines, process joins, journal files and profile writes are real;
// only deliberate stale-input and filesystem-failure controls are injected.
func linuxHostTUNPublicProtectionOff(ctx context.Context, a *app, session *desktopLinuxNodeSession, host *desktopLinuxNodeHost, scenario string) (*linuxHostTUNOffResult, error) {
	result := &linuxHostTUNOffResult{}
	transaction := host.transaction
	a.operationMu.Lock()
	err := linuxHostTUNRestoreCheck(ctx, session, host, func() error {
		a.mu.Lock()
		defer a.mu.Unlock()
		if session.active != nil || session.predecessor != transaction || session.off != nil || !host.closed || !host.released ||
			a.cmd != nil || a.state.Connected || a.state.Phase != "off" || a.profiles.Profiles[0].KillSwitchPolicy != "always" {
			return errors.New("public Always Disconnect did not retain its exact closed source")
		}
		return nil
	})
	a.operationMu.Unlock()
	if err != nil {
		return nil, err
	}
	if err := transaction.enter(ctx); err != nil {
		return nil, err
	}
	before := transaction.head
	before.Record = linuxprotection.CloneRecord(before.Record)
	err = transaction.baseline.ObserveClosed(ctx)
	retained := transaction.retired && transaction.engineJoined && !transaction.closed && !transaction.baselineReleased && before.Record.Committed.Target != nil
	transaction.gate <- struct{}{}
	if err != nil || !retained {
		return nil, errors.Join(err, errors.New("public Always Disconnect released its original native protection"))
	}
	if err := linuxHostTUNOffNetwork(ctx, false); err != nil {
		return nil, err
	}
	result.RetainedAlways = true
	value, err := linuxHostTUNOffSettings(ctx, a)
	if err != nil || value.EffectivePolicy != "always" || value.ProtectionStatus != "retained" || value.ProtectionProfileID != host.launch.profileID {
		return nil, errors.Join(err, errors.New("public protection status hid retained Linux Always"))
	}
	a.mu.Lock()
	beforeStore := cloneRouterProfileStore(a.profiles)
	a.mu.Unlock()
	// A matching source/hash cannot substitute for the retained original
	// transaction pointer while request decoding is in progress.
	foreign := &desktopLinuxNodeTransaction{gate: make(chan struct{}, 1), parent: transaction.parent,
		journal: transaction.journal, profileID: transaction.profileID, selection: transaction.selection, head: before}
	foreign.gate <- struct{}{}
	var mutationErr error
	body := &startupSettingsMutationReader{Reader: bytes.NewReader(linuxHostTUNOffBody(value)), mutate: func() {
		if mutationErr = session.enter(ctx); mutationErr != nil {
			return
		}
		session.predecessor = foreign
		session.gate <- struct{}{}
	}}
	rejected := httptest.NewRecorder()
	a.profileProtectionSettings(rejected, httptest.NewRequest(http.MethodPost, "/api/profile/protection", body).WithContext(ctx))
	if err := session.enter(ctx); err != nil {
		return nil, err
	}
	session.predecessor = transaction
	session.gate <- struct{}{}
	if mutationErr != nil || rejected.Code != http.StatusConflict || transaction.baseline.ObserveClosed(ctx) != nil {
		return nil, errors.Join(mutationErr, errors.New("public Linux Off adopted a replacement source during request decoding"))
	}
	result.ReplacementRejected = true
	// Generic settings are not an alternative route around actual native Off.
	rejected = httptest.NewRecorder()
	a.profileSettings(rejected, httptest.NewRequest(http.MethodPost, "/api/profile/settings", bytes.NewBufferString(`{"kill_switch_policy":"off"}`)).WithContext(ctx))
	if rejected.Code != http.StatusConflict || transaction.baseline.ObserveClosed(ctx) != nil {
		return nil, errors.New("broader settings bypassed original Linux Always removal")
	}
	path := a.cfg.ProfilesFile
	if scenario == "public-off-save-retry" {
		// Hold the actual old private store at a fixture-owned path, then make
		// atomic publication fail at its unchanged intended destination.
		backup := path + ".off-fixture-original"
		if err := os.Rename(path, backup); err != nil {
			return nil, err
		}
		if err := os.Mkdir(path, 0700); err != nil {
			_ = os.Rename(backup, path)
			return nil, err
		}
		defer func() {
			if info, err := os.Lstat(path); err == nil && info.IsDir() {
				_ = os.Remove(path)
				_ = os.Rename(backup, path)
			}
		}()
		response := httptest.NewRecorder()
		a.profileProtectionSettings(response, httptest.NewRequest(http.MethodPost, "/api/profile/protection", bytes.NewReader(linuxHostTUNOffBody(value))).WithContext(ctx))
		if response.Code != http.StatusInternalServerError {
			return nil, fmt.Errorf("actual failed Linux Off save returned %d: %s", response.Code, response.Body.String())
		}
		pending, err := linuxHostTUNOffSettings(ctx, a)
		if err != nil || pending.ProtectionStatus != "off-unsaved" || pending.EffectivePolicy != "off" || pending.KillSwitchPolicy != "always" || pending.ProfileToken != value.ProfileToken {
			return nil, errors.Join(err, errors.New("actual native release/save failure lost its same truthful retry"))
		}
		if err := session.enter(ctx); err != nil {
			return nil, err
		}
		accepted := session.off
		owned := accepted != nil && accepted.transaction == transaction && session.predecessor == transaction && !accepted.profileWritten
		session.gate <- struct{}{}
		if !owned || mobiletor.ReadDesktopLinuxNodeAbsence(ctx, host.selection.SessionID) != nil {
			return nil, errors.New("unsaved Linux Off lost its original absent native creator")
		}
		blocked := httptest.NewRecorder()
		a.connect(blocked, httptest.NewRequest(http.MethodPost, "/api/connect", bytes.NewBufferString(`{"mode":"shadowsocks"}`)).WithContext(ctx))
		if blocked.Code != http.StatusConflict {
			return nil, errors.New("unsaved Linux Off admitted another public connection")
		}
		if err := os.Remove(path); err != nil {
			return nil, err
		}
		if err := os.Rename(backup, path); err != nil {
			return nil, err
		}
		value = pending
		result.SaveRetried = true
	}
	response := httptest.NewRecorder()
	a.profileProtectionSettings(response, httptest.NewRequest(http.MethodPost, "/api/profile/protection", bytes.NewReader(linuxHostTUNOffBody(value))).WithContext(ctx))
	if response.Code != http.StatusOK {
		return nil, fmt.Errorf("public Linux Off failed: %d %s", response.Code, response.Body.String())
	}
	if err := session.enter(ctx); err != nil {
		return nil, err
	}
	if session.active != nil || session.predecessor != nil || session.off != nil {
		session.gate <- struct{}{}
		return nil, errors.New("successful Linux Off retained its removal owner")
	}
	session.gate <- struct{}{}
	if err := transaction.enter(ctx); err != nil {
		return nil, err
	}
	closed := transaction.closed && transaction.released && transaction.baselineReleased && transaction.off != nil && transaction.off.settled
	transaction.gate <- struct{}{}
	if !closed || mobiletor.ReadDesktopLinuxNodeAbsence(ctx, host.selection.SessionID) != nil {
		return nil, errors.New("successful Linux Off lacked joined original cleanup and native absence")
	}
	journal := session.journal
	if err := journal.enter(ctx); err != nil {
		return nil, err
	}
	settled, _, readErr := journal.readSelection()
	prior, priorErr := journal.readFile(journal.slots[1-settled.Slot], linuxprotection.JournalRecordLimit)
	journal.gate <- struct{}{}
	intent, decodeErr := linuxprotection.ParseJournalRecord(prior)
	if readErr != nil || priorErr != nil || decodeErr != nil || settled.Record.Phase != "settled" || settled.Record.Committed.Target != nil ||
		settled.Record.Sequence != before.Record.Sequence+2 || intent.Sequence != before.Record.Sequence+1 || intent.Intent == nil || intent.Intent.Action != "off" ||
		!reflect.DeepEqual(intent.Committed, before.Record.Committed) || intent.Intent.ProfileID != host.launch.profileID || intent.Intent.ProfileRevision != profileStartupSettingsToken(beforeStore.Profiles[0]) {
		return nil, errors.Join(readErr, priorErr, decodeErr, errors.New("explicit Linux Off skipped its original durable intent or exact empty settlement"))
	}
	result.JournalSettled = true
	expected, err := profileProtectionOffResult(beforeStore.Profiles[0])
	if err != nil {
		return nil, err
	}
	beforeStore.Profiles[0] = expected
	stored, err := readPrivateRegular(path, 64<<10)
	var saved common.RouterProfileStore
	if err != nil || json.Unmarshal(stored, &saved) != nil || !reflect.DeepEqual(saved, beforeStore) || intent.Intent.ResultProfileRevision != profileStartupSettingsToken(expected) {
		return nil, errors.Join(err, errors.New("public Linux Off changed another private profile field or omitted its exact saved result"))
	}
	result.ProfileSaved = true
	replayed := httptest.NewRecorder()
	a.profileProtectionSettings(replayed, httptest.NewRequest(http.MethodPost, "/api/profile/protection", bytes.NewReader(linuxHostTUNOffBody(value))).WithContext(ctx))
	if replayed.Code != http.StatusConflict {
		return nil, errors.New("consumed Linux Off token authorized a new operation")
	}
	result.ReplayRejected = true
	if err := linuxHostTUNOffNetwork(ctx, true); err != nil {
		return nil, err
	}
	result.NetworkReleased = true
	return result, nil
}
