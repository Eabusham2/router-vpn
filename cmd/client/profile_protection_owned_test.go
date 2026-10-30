package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"testing"
	"time"

	"router-vpn/internal/common"
	"router-vpn/internal/mobiletor"
)

func ownedProtectionGet(t *testing.T, a *app) profileProtectionSettings {
	t.Helper()
	w := httptest.NewRecorder()
	a.profileProtectionSettings(w, httptest.NewRequest(http.MethodGet, "/api/profile/protection", nil))
	var value profileProtectionSettings
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &value) != nil || len(value.ProfileToken) != 64 {
		t.Fatalf("owned protection status failed: %d %s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "private-token") || strings.Contains(w.Body.String(), "baseline_sha256") || strings.Contains(w.Body.String(), "session_id") {
		t.Fatal("public protection state exposed private/native authority")
	}
	return value
}

func ownedProtectionBody(t *testing.T, value profileProtectionSettings, policy string) []byte {
	t.Helper()
	raw, err := json.Marshal(map[string]string{"profile_id": value.ProfileID, "profile_token": value.ProfileToken, "kill_switch_policy": policy})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestProfileProtectionOwnedOffCommitsOnlyAfterExactAbsence(t *testing.T) {
	f := newDesktopProtectionOffFixture(t)
	capture := ownedProtectionGet(t, f.a)
	if capture.EffectivePolicy != "always" || capture.ProtectionStatus != "retained" || capture.ProtectionProfileID != f.profile.ID {
		t.Fatal("retained effective protection was not distinguished from its preference")
	}
	before := cloneRouterProfileStore(f.a.profiles)
	w := postProtectionForTest(f.a, bytes.NewReader(ownedProtectionBody(t, capture, "off")))
	if w.Code != http.StatusOK || f.calls != 1 || f.kernel.target != nil || !f.owners[0].closed || f.a.nodeProtection != nil {
		t.Fatalf("explicit owned Off did not join/prove/persist/retire: %d %s", w.Code, w.Body.String())
	}
	before.Profiles[0].KillSwitchPolicy, before.Profiles[0].KillSwitch = "off", false
	if !reflect.DeepEqual(before, f.a.profiles) {
		t.Fatal("explicit Off changed captured credentials, DNS, MTU or unrelated fields")
	}
	var saved common.RouterProfileStore
	raw, err := os.ReadFile(f.a.cfg.ProfilesFile)
	if err := common.NormalizeRouterProfileStore(&before); err != nil {
		t.Fatal(err)
	}
	if err != nil || json.Unmarshal(raw, &saved) != nil || !reflect.DeepEqual(saved, before) {
		t.Fatal("successful Off did not persist the exact changed preference", err)
	}
	if value := ownedProtectionGet(t, f.a); value.KillSwitchPolicy != "off" || value.ProtectionStatus != "" || value.ProfileToken == capture.ProfileToken {
		t.Fatal("completed Off retained a stale request revision or pending state")
	}
	w = postProtectionForTest(f.a, bytes.NewReader(ownedProtectionBody(t, capture, "off")))
	if w.Code != http.StatusConflict || f.calls != 1 {
		t.Fatal("consumed Off revision authorized another removal")
	}
}

func TestProfileProtectionOwnedOffSaveFailureIsTruthfulAndRetryable(t *testing.T) {
	f := newDesktopProtectionOffFixture(t)
	capture := ownedProtectionGet(t, f.a)
	path := f.a.cfg.ProfilesFile
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	f.a.cfg.ProfilesFile = t.TempDir() // Actual private atomic save failure.
	w := postProtectionForTest(f.a, bytes.NewReader(ownedProtectionBody(t, capture, "off")))
	if w.Code != http.StatusInternalServerError || f.a.nodeProtection != f.slot || f.kernel.target != nil || f.calls != 1 {
		t.Fatalf("native absence/save failure lost its owner: %d %s", w.Code, w.Body.String())
	}
	status := ownedProtectionGet(t, f.a)
	if status.KillSwitchPolicy != "always" || status.EffectivePolicy != "off" || status.ProtectionStatus != "off-unsaved" ||
		status.ProfileToken != capture.ProfileToken || !strings.Contains(status.Message, "could not be saved") || f.slot.provedEmpty() {
		t.Fatal("failed persistence pretended Always was restored or Off was saved")
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) || f.a.profiles.Profiles[0].KillSwitchPolicy != "always" {
		t.Fatal("failed persistence mutated the prior saved preference", err)
	}
	owner := f.slot.pendingOff().owner
	f.a.cfg.ProfilesFile = path
	w = postProtectionForTest(f.a, bytes.NewReader(ownedProtectionBody(t, status, "off")))
	if w.Code != http.StatusOK || f.calls != 1 || f.owners[0] != owner || f.a.nodeProtection != nil || f.a.profiles.Profiles[0].KillSwitchPolicy != "off" {
		t.Fatalf("off-unsaved retry did not save the same operation: %d %s", w.Code, w.Body.String())
	}
}

func TestProfileProtectionOwnedPendingBlocksUnrelatedMutation(t *testing.T) {
	f := newDesktopProtectionOffFixture(t)
	f.closeFail = true
	capture := ownedProtectionGet(t, f.a)
	w := postProtectionForTest(f.a, bytes.NewReader(ownedProtectionBody(t, capture, "off")))
	if w.Code != http.StatusServiceUnavailable || f.slot.pendingOff() == nil {
		t.Fatal("fixture Off did not remain pending")
	}
	before := cloneRouterProfileStore(f.a.profiles)
	request := httptest.NewRequest(http.MethodPost, "/api/profile/settings", strings.NewReader(`{"kill_switch_policy":"off"}`))
	for _, internal := range []bool{false, true} {
		r := request
		if internal {
			r = withInternalMutationContext(r)
		}
		if release, err := f.a.beginMutationOperation(r); err == nil {
			release()
			t.Fatal("pending Off admitted a profile mutation")
		}
	}
	if release, err := f.a.beginNodeBoundOperation(); err == nil {
		release()
		t.Fatal("pending Off admitted a node-bound operation")
	}
	if _, release, err := f.a.beginConnectionTransaction(); err == nil {
		release()
		t.Fatal("pending Off admitted a connection")
	}
	w = httptest.NewRecorder()
	f.a.profileSettings(w, request)
	if w.Code != http.StatusConflict || !reflect.DeepEqual(before, f.a.profiles) {
		t.Fatal("settings editor bypassed pending Off")
	}
	w = postProtectionForTest(f.a, bytes.NewReader(ownedProtectionBody(t, ownedProtectionGet(t, f.a), "on-connect")))
	if w.Code != http.StatusConflict || f.calls != 1 || !reflect.DeepEqual(before, f.a.profiles) {
		t.Fatal("pending Off became another preference transaction")
	}
}

func TestProfileProtectionOwnedRejectsStaleOrMalformedBeforeRemoval(t *testing.T) {
	for _, fault := range []string{"selected", "credential", "generation", "foreign-binding", "unknown", "busy", "command", "closing", "cancel", "mixed", "duplicate", "case-alias", "bad-policy", "response-field", "extra-object"} {
		t.Run(fault, func(t *testing.T) {
			f := newDesktopProtectionOffFixture(t)
			capture := ownedProtectionGet(t, f.a)
			body := ownedProtectionBody(t, capture, "off")
			ctx := context.Background()
			switch fault {
			case "selected":
				f.a.profiles.SelectedID = "missing"
			case "credential":
				f.a.profiles.Profiles[0].APIToken = "replacement-private-token"
			case "generation":
				f.slot.generation++
			case "foreign-binding":
				f.slot.binding.ProfileID = "another-node"
			case "unknown":
				f.slot.known = false
			case "busy":
				f.a.state.Phase = "future-transition"
			case "command":
				f.a.cmd = exec.Command("captured-operation-only")
			case "closing":
				f.a.closing = true
			case "cancel":
				cancelled, cancel := context.WithCancel(ctx)
				cancel()
				ctx = cancelled
			case "mixed":
				body = append(body[:len(body)-1], []byte(`,"dns_host":"1.1.1.1"}`)...)
			case "duplicate":
				body = append(body[:len(body)-1], []byte(`,"kill_switch_policy":"always"}`)...)
			case "case-alias":
				body = bytes.Replace(body, []byte(`"kill_switch_policy"`), []byte(`"KILL_SWITCH_POLICY"`), 1)
			case "bad-policy":
				body = ownedProtectionBody(t, capture, "none")
			case "response-field":
				body = append(body[:len(body)-1], []byte(`,"effective_policy":"off"}`)...)
			case "extra-object":
				body = append(body, []byte(` {}`)...)
			}
			before := cloneRouterProfileStore(f.a.profiles)
			w := httptest.NewRecorder()
			f.a.profileProtectionSettings(w, httptest.NewRequest(http.MethodPost, "/api/profile/protection", bytes.NewReader(body)).WithContext(ctx))
			if w.Code < 400 || f.calls != 0 || f.slot.pendingOff() != nil || !reflect.DeepEqual(before, f.a.profiles) || !reflect.DeepEqual(f.kernel.target, &f.target) {
				t.Fatalf("invalid Off changed source/native ownership: %d %s", w.Code, w.Body.String())
			}
		})
	}
}

func TestProfileProtectionOwnedRechecksAfterBodyBeforeCapture(t *testing.T) {
	for _, fault := range []string{"revision", "selection", "slot", "measurement"} {
		t.Run(fault, func(t *testing.T) {
			f := newDesktopProtectionOffFixture(t)
			capture := ownedProtectionGet(t, f.a)
			reader := &startupSettingsMutationReader{Reader: bytes.NewReader(ownedProtectionBody(t, capture, "off")), mutate: func() {
				f.a.mu.Lock()
				defer f.a.mu.Unlock()
				switch fault {
				case "revision":
					f.a.profiles.Profiles[0].DNSHost = "1.1.1.1"
				case "selection":
					f.a.profiles.SelectedID = "replacement"
				case "slot":
					f.a.nodeProtection = &desktopNodeProtectionSlot{}
				case "measurement":
					f.a.profiles.Profiles[0].UseCount = 99
				}
			}}
			w := postProtectionForTest(f.a, reader)
			if fault == "measurement" {
				if w.Code != http.StatusOK || f.a.profiles.Profiles[0].UseCount != 99 {
					t.Fatal("Off lost concurrent measurement metadata")
				}
			} else if w.Code != http.StatusConflict || f.calls != 0 || f.slot.pendingOff() != nil {
				t.Fatalf("body-time replacement acquired removal authority: %d", w.Code)
			}
		})
	}
}

func TestProfileProtectionOwnedCancelledRemovalResumesDuringCleanup(t *testing.T) {
	for _, phase := range []string{"armed", "absence"} {
		t.Run(phase, func(t *testing.T) {
			f := newDesktopProtectionOffFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if phase == "armed" {
				f.afterMake = cancel
			} else {
				f.afterRead = func(target *mobiletor.DesktopWindowsProtectionTarget) {
					if target == nil {
						cancel()
					}
				}
			}
			capture := ownedProtectionGet(t, f.a)
			w := httptest.NewRecorder()
			f.a.profileProtectionSettings(w, httptest.NewRequest(http.MethodPost, "/api/profile/protection", bytes.NewReader(ownedProtectionBody(t, capture, "off"))).WithContext(ctx))
			pending := f.slot.pendingOff()
			if w.Code < 400 || pending == nil || pending.owner == nil || !pending.prepared || f.a.profiles.Profiles[0].KillSwitchPolicy != "always" {
				t.Fatal("cancelled accepted Off lost its exact owner or rewrote preference")
			}
			if phase == "absence" && ownedProtectionGet(t, f.a).ProtectionStatus != "off-unsaved" {
				t.Fatal("cancelled save hid native absence")
			}
			f.afterMake, f.afterRead = nil, nil
			f.a.closing, f.a.state.Phase = true, "stopping"
			f.a.operationMu.Lock()
			err := f.a.releaseCapturedDesktopNodeProtection(f.slot)
			f.a.operationMu.Unlock()
			if err != nil || f.calls != 1 || f.kernel.target != nil || f.a.nodeProtection != nil || f.a.profiles.Profiles[0].KillSwitchPolicy != "off" {
				t.Fatal("controller cleanup did not finish the same accepted Off and save", err)
			}
		})
	}
}

func TestProfileProtectionOwnedBroaderOffEditorCannotBypassExactRemoval(t *testing.T) {
	f := newDesktopProtectionOffFixture(t)
	w := httptest.NewRecorder()
	f.a.profileSettings(w, httptest.NewRequest(http.MethodPost, "/api/profile/settings", strings.NewReader(`{"kill_switch_policy":"off"}`)))
	if w.Code != http.StatusConflict || f.calls != 0 || f.a.profiles.Profiles[0].KillSwitchPolicy != "always" || f.slot.pendingOff() != nil {
		t.Fatal("broader saved preference editor silently bypassed retained protection")
	}
}

func TestProfileProtectionOwnedNativeFailureDoesNotSaveOff(t *testing.T) {
	for _, fault := range []string{"join", "read"} {
		t.Run(fault, func(t *testing.T) {
			f := newDesktopProtectionOffFixture(t)
			before, err := os.ReadFile(f.a.cfg.ProfilesFile)
			if err != nil {
				t.Fatal(err)
			}
			if fault == "join" {
				f.closeFail = true
			} else {
				f.afterMake = func() { f.kernel.readFail = true }
			}
			capture := ownedProtectionGet(t, f.a)
			w := postProtectionForTest(f.a, bytes.NewReader(ownedProtectionBody(t, capture, "off")))
			after, err := os.ReadFile(f.a.cfg.ProfilesFile)
			if w.Code != http.StatusServiceUnavailable || err != nil || !bytes.Equal(before, after) ||
				f.a.profiles.Profiles[0].KillSwitchPolicy != "always" || f.slot.pendingOff() == nil || f.slot.pendingOff().removed {
				t.Fatal("failed native join or absence proof saved Off or discarded its pending capture")
			}
		})
	}
}

func TestProfileProtectionOwnedUnsavedRetryRejectsReplacement(t *testing.T) {
	for _, fault := range []string{"profile", "native", "slot"} {
		t.Run(fault, func(t *testing.T) {
			f := newDesktopProtectionOffFixture(t)
			path := f.a.cfg.ProfilesFile
			f.a.cfg.ProfilesFile = t.TempDir()
			capture := ownedProtectionGet(t, f.a)
			if w := postProtectionForTest(f.a, bytes.NewReader(ownedProtectionBody(t, capture, "off"))); w.Code != http.StatusInternalServerError {
				t.Fatal("fixture did not reach off-unsaved")
			}
			pending := f.slot.pendingOff()
			f.a.cfg.ProfilesFile = path
			switch fault {
			case "profile":
				f.a.profiles.Profiles[0].DNSHost = "1.1.1.1"
			case "native":
				f.kernel.target = copyDesktopNodeProtectionTarget(&f.target)
				f.kernel.target.BaselineSHA256 = strings.Repeat("f", 64)
			case "slot":
				f.a.nodeProtection = &desktopNodeProtectionSlot{}
			}
			before := cloneRouterProfileStore(f.a.profiles)
			w := postProtectionForTest(f.a, bytes.NewReader(ownedProtectionBody(t, capture, "off")))
			if w.Code < 400 || f.calls != 1 || f.slot.pendingOff() != pending || !reflect.DeepEqual(before, f.a.profiles) {
				t.Fatal("unsaved retry adopted another profile, baseline or application slot")
			}
			if fault == "native" {
				state := ownedProtectionGet(t, f.a)
				if state.EffectivePolicy != "unknown" || state.ProtectionStatus != "off-pending" {
					t.Fatal("failed new absence read was reported as current Off")
				}
			}
		})
	}
}

func TestProfileProtectionOwnedConcurrentRequestKeepsSingleRemoval(t *testing.T) {
	f := newDesktopProtectionOffFixture(t)
	body := ownedProtectionBody(t, ownedProtectionGet(t, f.a), "off")
	entered, allowClose := make(chan struct{}), make(chan struct{})
	f.beforeClose = func(ctx context.Context) error {
		close(entered)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-allowClose:
			return nil
		}
	}
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() { done <- postProtectionForTest(f.a, bytes.NewReader(body)) }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("exact native close was never entered")
	}
	// The second HTTP request and an unrelated settings request fail at the
	// application transaction lock without waiting on the native slot mutex.
	w := postProtectionForTest(f.a, bytes.NewReader(body))
	if w.Code != http.StatusConflict {
		close(allowClose)
		<-done
		t.Fatal("parallel Off was not serialized")
	}
	request := httptest.NewRequest(http.MethodPost, "/api/profile/settings", strings.NewReader(`{}`))
	if release, err := f.a.beginMutationOperation(request); err == nil {
		release()
		close(allowClose)
		<-done
		t.Fatal("parallel settings operation entered accepted Off")
	}
	close(allowClose)
	select {
	case w = <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("captured Off did not join after explicit native completion")
	}
	if w.Code != http.StatusOK || f.calls != 1 || len(f.owners) != 1 || f.a.nodeProtection != nil {
		t.Fatal("serialized Off acquired or abandoned more than one exact native owner")
	}
}
