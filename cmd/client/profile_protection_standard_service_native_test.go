//go:build linux && routervpn_controller_privileged

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// Actual HTTP handlers, private profile/state files, flock, original service
// engine and authenticated controller peer are exercised. Only nft/TUN
// observations use the existing explicit native-policy model.
func standardServiceProtectionUIFixture(t *testing.T, mode string) (*app, *linuxStandardService, *legacyProtectionModel, *legacyExitProtectionSlot, *linuxStandardServiceProtectionClient) {
	t.Helper()
	s, f, model := linuxStandardServiceRuntimeFixture(t, "always")
	// Shipping startup decodes the canonical saved profile, including the
	// RouterProfile JSON defaults; use those actual bytes for the UI owner.
	body, err := os.ReadFile(f.a.cfg.ProfilesFile)
	if err != nil || json.Unmarshal(body, &f.a.profiles) != nil {
		t.Fatal("canonical UI profile", err)
	}
	s.tunAbsent = func() error { return nil }
	s.protectionAbsence = func(context.Context) error {
		model.mu.Lock()
		defer model.mu.Unlock()
		if len(model.tables) != 0 {
			return errors.New("native model retains a protection table")
		}
		return nil
	}
	peer, connection, _ := linuxStandardPeerFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if mode == "boot" {
		f.a.profiles.Profiles[0].Endpoint = "203.0.113.77"
		if err := f.a.persistProfilesLocked(); err != nil {
			t.Fatal(err)
		}
		linuxStandardServicePreviousBootState(t, f.root, "control", "203.0.113.77")
		if err := s.reassertWithObservers(ctx, s.tunAbsent, s.protectionAbsence, model.create); err != nil {
			t.Fatal(err)
		}
	} else {
		request, directory := linuxStandardServiceRequestFixture(t, f)
		if err := s.handle(ctx, peer, request, []*os.File{directory}); err != nil {
			t.Fatal(err)
		}
		waitLegacyOffEngine(t, f)
		if mode != "active" {
			if err := s.handle(ctx, peer, linuxStandardServiceTestAction(request, "stop", true), nil); err != nil {
				t.Fatal(err)
			}
			assertLegacyOffJoined(t, s.session.owner)
		}
	}
	raw, ok := legacyStandardProtectionOwners.Load(s.app)
	if !ok {
		t.Fatal("fixture lost original Always creator")
	}
	slot := raw.(*legacyExitProtectionSlot)
	image, _ := os.Stat("/proc/self/exe")
	namespace, _ := os.Stat("/proc/thread-self/ns/net")
	executable, _ := os.Executable()
	client := &linuxStandardServiceProtectionClient{app: f.a}
	client.exchange = func(ctx context.Context, request linuxStandardServiceRequest) (*linuxStandardServiceProtectionData, error) {
		request.BudgetMS = 15000
		if deadline, ok := ctx.Deadline(); ok {
			request.DeadlineNS = deadline.UnixNano()
		}
		actual, err := captureLinuxStandardServicePeer(ctx, connection, image, []string{executable, "-test.run=^TestLinuxStandardServicePeerFixture$"}, namespace)
		if err != nil {
			return nil, err
		}
		result, err := s.protectionRequest(ctx, actual, request)
		<-s.gate
		retained := s.session != nil && s.session.peer == actual || s.protectionView != nil && s.protectionView.peer == actual
		s.gate <- struct{}{}
		if !retained {
			_ = actual.Close()
		}
		return result, err
	}
	linuxStandardServiceProtectionClients.Store(f.a, client)
	t.Cleanup(func() {
		linuxStandardServiceProtectionClients.Delete(f.a)
		if s.protectionView != nil && s.protectionView.peer != nil {
			_ = s.protectionView.peer.Close()
		}
	})
	return f.a, s, model, slot, client
}

func standardServiceUIProtection(t *testing.T, a *app) profileProtectionSettings {
	t.Helper()
	response := httptest.NewRecorder()
	a.profileProtectionSettings(response, httptest.NewRequest(http.MethodGet, "/api/profile/protection", nil))
	var result profileProtectionSettings
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &result) != nil || len(result.ProfileToken) != 64 {
		t.Fatal("shipping protection GET lost original selected view", response.Code, response.Body.String())
	}
	return result
}

func standardServiceUIOff(t *testing.T, a *app, view profileProtectionSettings, ctx context.Context) *httptest.ResponseRecorder {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"profile_id": view.ProfileID, "profile_token": view.ProfileToken, "kill_switch_policy": "off"})
	response := httptest.NewRecorder()
	a.profileProtectionSettings(response, httptest.NewRequest(http.MethodPost, "/api/profile/protection", bytes.NewReader(body)).WithContext(ctx))
	return response
}

func TestLinuxStandardServiceUIExplicitOffReleasesOriginalLiveOrBootCreator(t *testing.T) {
	for _, mode := range []string{"joined", "boot"} {
		t.Run(mode, func(t *testing.T) {
			a, s, model, slot, _ := standardServiceProtectionUIFixture(t, mode)
			view := standardServiceUIProtection(t, a)
			if view.ProtectionStatus != "retained" || view.EffectivePolicy != "always" {
				t.Fatal("service-held Always was invisible", view)
			}
			before := cloneRouterProfileStore(a.profiles)
			response := standardServiceUIOff(t, a, view, context.Background())
			if response.Code != http.StatusOK {
				capture := a.captureProfileProtection(a.profiles.Profiles[0])
				if capture.platform != nil && capture.platform.standard != nil {
					current := capture.platform.standard
					t.Logf("source comparison: profile=%v result=%v path=%v app=%v cmd=%v node=%v busy=%v", capture.revision == current.ProfileRevision, capture.resultRevision == current.ResultRevision, a.cfg.ProfilesFile == capture.platform.standardProfilePath, current.currentAppLocked(a), a.cmd != nil, a.nodeProtection != nil, profileSettingsBusy(a.state.Connected, a.state.Phase))
					left, right := reflect.ValueOf(a.profiles.Profiles[0]), reflect.ValueOf(s.app.profiles.Profiles[0])
					typ := left.Type()
					for i := 0; i < left.NumField(); i++ {
						if !reflect.DeepEqual(left.Field(i).Interface(), right.Field(i).Interface()) {
							t.Log("profile field differs:", typ.Field(i).Name)
						}
					}
				}
				t.Fatal("shipping explicit Off failed", response.Code, response.Body.String())
			}
			if !slot.closed || !slot.removed || !slot.stateRemoved {
				t.Fatal("HTTP200 saved Off without original native retirement")
			}
			if _, exists := legacyStandardProtectionOwners.Load(s.app); exists {
				t.Fatal("explicit Off retained original creator map")
			}
			if _, err := os.Stat(filepath.Join(s.root, "run", "kill-switch.json")); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("explicit Off lost actual state absence", err)
			}
			before.Profiles[0].KillSwitchPolicy, before.Profiles[0].KillSwitch = "off", false
			if !reflect.DeepEqual(before, a.profiles) {
				t.Fatal("explicit Off changed unrelated source settings")
			}
			model.mu.Lock()
			events := append([]string(nil), model.events...)
			empty := len(model.tables) == 0
			model.mu.Unlock()
			if !empty || len(events) != 2 || !strings.HasPrefix(events[0], "create:") || !strings.HasPrefix(events[1], "delete:") {
				t.Fatal("explicit Off required a new runtime or released another creator", events)
			}
			if after := standardServiceUIProtection(t, a); after.KillSwitchPolicy != "off" || after.ProtectionStatus != "" {
				t.Fatal("completed Off stayed pending", after)
			}
		})
	}
}

func TestLinuxStandardServiceUIOffRejectsChangedSourceOrNativeOwner(t *testing.T) {
	for _, kind := range []string{"stale-profile", "stale-selection", "profile-path", "foreign-table", "foreign-state", "replacement-controller", "active"} {
		t.Run(kind, func(t *testing.T) {
			mode := "joined"
			if kind == "active" {
				mode = "active"
			}
			a, s, model, slot, _ := standardServiceProtectionUIFixture(t, mode)
			view := standardServiceUIProtection(t, a)
			switch kind {
			case "stale-profile":
				a.profiles.Profiles[0].DNSHost = "8.8.8.8"
				if err := a.persistProfilesLocked(); err != nil {
					t.Fatal(err)
				}
			case "stale-selection":
				a.profiles.SelectedID = "missing"
			case "profile-path":
				a.cfg.ProfilesFile = filepath.Join(s.root, "replacement-profiles.json")
			case "foreign-table":
				original := slot.kernel.(*legacyProtectionModelOwner)
				model.mu.Lock()
				model.tables[original.receipt.Session] = &legacyProtectionModelOwner{model: model, receipt: original.receipt}
				model.mu.Unlock()
			case "foreign-state":
				if err := os.WriteFile(filepath.Join(s.root, "run", "kill-switch.json"), []byte(`{"foreign":true}`), 0600); err != nil {
					t.Fatal(err)
				}
			case "replacement-controller":
				a.localController = &ownedDesktopController{}
			}
			response := standardServiceUIOff(t, a, view, context.Background())
			if response.Code == http.StatusOK || slot.removed || slot.closed || a.profiles.Profiles[0].KillSwitchPolicy != "always" {
				t.Fatal("stale explicit Off released original/foreign authority or saved false Off", kind, response.Code, response.Body.String())
			}
		})
	}
}

func TestLinuxStandardServiceUIOffRetainsOriginalRetryAfterCancellationOrSaveFailure(t *testing.T) {
	for _, kind := range []string{"cancel-after-native-delete", "profile-save-failure"} {
		t.Run(kind, func(t *testing.T) {
			a, s, model, slot, client := standardServiceProtectionUIFixture(t, "joined")
			view := standardServiceUIProtection(t, a)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			profilePath := a.cfg.ProfilesFile
			originalProfile, err := os.ReadFile(profilePath)
			if err != nil {
				t.Fatal(err)
			}
			originalExchange := client.exchange
			if kind == "cancel-after-native-delete" {
				model.beforeDelete = cancel
			} else {
				client.exchange = func(ctx context.Context, request linuxStandardServiceRequest) (*linuxStandardServiceProtectionData, error) {
					result, err := originalExchange(ctx, request)
					if err == nil && request.Action == "protection-release" {
						if removeErr := os.Remove(profilePath); removeErr != nil {
							return nil, removeErr
						}
						if mkdirErr := os.Mkdir(profilePath, 0700); mkdirErr != nil {
							return nil, mkdirErr
						}
					}
					return result, err
				}
				defer func() { client.exchange = originalExchange }()
			}
			response := standardServiceUIOff(t, a, view, ctx)
			if response.Code == http.StatusOK || !slot.removed || s.protectionView == nil || !s.protectionView.data.Pending {
				t.Fatal("interrupted explicit Off erased original retry or claimed completion", response.Code, response.Body.String())
			}
			if err := s.prepareIdleShutdownWithObservers(context.Background(), s.tunAbsent, s.protectionAbsence); err == nil {
				t.Fatal("upgrade discarded pending explicit Off save")
			}
			model.beforeDelete = nil
			if kind == "profile-save-failure" {
				if err := os.Remove(profilePath); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(profilePath, originalProfile, 0600); err != nil {
					t.Fatal(err)
				}
				// The original exchange remains; only the deliberate write fault ends.
				client.exchange = originalExchange
			}
			retry := standardServiceUIProtection(t, a)
			if retry.ProfileToken != view.ProfileToken || !strings.HasPrefix(retry.ProtectionStatus, "off-") {
				t.Fatal("Off retry replaced original accepted token", view, retry)
			}
			response = standardServiceUIOff(t, a, retry, context.Background())
			if response.Code != http.StatusOK || !slot.closed || a.profiles.Profiles[0].KillSwitchPolicy != "off" {
				t.Fatal("original Off retry failed", response.Code, response.Body.String())
			}
			model.mu.Lock()
			events := append([]string(nil), model.events...)
			model.mu.Unlock()
			if len(events) != 2 {
				t.Fatal("Off retry recreated or repeatedly deleted native protection", events)
			}
		})
	}
}

func TestLinuxStandardServiceUIOwnedProtectionCannotBecomeSavedOnlyOff(t *testing.T) {
	a, _, _, slot, _ := standardServiceProtectionUIFixture(t, "joined")
	response := httptest.NewRecorder()
	a.profileSettings(response, httptest.NewRequest(http.MethodPost, "/api/profile/settings", strings.NewReader(`{"kill_switch_policy":"off"}`)))
	if response.Code != http.StatusConflict || slot.removed || a.profiles.Profiles[0].KillSwitchPolicy != "always" {
		t.Fatal("broad settings bypassed original service Off", response.Code, response.Body.String())
	}
}

func TestLinuxStandardServiceUIOffRejectsStaleCompletionAfterNativeRelease(t *testing.T) {
	for _, kind := range []string{"profile", "controller", "local-adapter"} {
		t.Run(kind, func(t *testing.T) {
			a, s, _, slot, client := standardServiceProtectionUIFixture(t, "joined")
			view := standardServiceUIProtection(t, a)
			originalExchange := client.exchange
			var replacement *linuxStandardServiceLaunch
			client.exchange = func(ctx context.Context, request linuxStandardServiceRequest) (*linuxStandardServiceProtectionData, error) {
				result, err := originalExchange(ctx, request)
				if err == nil && request.Action == "protection-release" {
					a.mu.Lock()
					defer a.mu.Unlock()
					switch kind {
					case "profile":
						a.profiles.Profiles[0].DNSHost = "8.8.8.8"
						err = a.persistProfilesLocked()
					case "controller":
						a.localController = &ownedDesktopController{}
					case "local-adapter":
						replacement = &linuxStandardServiceLaunch{request: linuxStandardServiceRequest{Session: strings.Repeat("9", 32)}}
						linuxStandardServiceOwners.Store(a, replacement)
					}
				}
				return result, err
			}
			defer linuxStandardServiceOwners.Delete(a)
			response := standardServiceUIOff(t, a, view, context.Background())
			if response.Code == http.StatusOK || !slot.removed || !slot.closed || a.profiles.Profiles[0].KillSwitchPolicy != "always" || s.protectionView == nil || !s.protectionView.data.Pending {
				t.Fatal("stale native completion overwrote newer application identity or erased pending original release", response.Code, response.Body.String())
			}
			if replacement != nil {
				if actual, exists := linuxStandardServiceOwners.Load(a); !exists || actual != replacement {
					t.Fatal("stale Off cleared newer local runtime adapter")
				}
			}
		})
	}
}

func TestLinuxStandardServiceUIParentAndServiceOwnershipPrecedence(t *testing.T) {
	for _, kind := range []string{"parent-only", "service-only", "both", "active-unowned", "unknown-service", "unknown-unowned-table", "proved-empty"} {
		t.Run(kind, func(t *testing.T) {
			parent := &desktopPlatformProtectionCapture{profileID: "parent", policy: "always"}
			service := &linuxStandardServiceProtectionCapture{Available: true, linuxStandardServiceProtectionData: linuxStandardServiceProtectionData{Owned: false}}
			switch kind {
			case "parent-only":
				service.ScopedAbsent = true
			case "service-only":
				parent = nil
				service.Owned = true
			case "both":
				service.Owned = true
			case "active-unowned":
				service.Active = true
			case "unknown-service":
				service.Available = false
				service.Failure = errors.New("original peer lost")
			case "unknown-unowned-table":
				parent = nil
				service.Failure = errors.New("unowned table remains")
			case "proved-empty":
				parent = nil
				service.AbsenceProved = true
			}
			result := combineLinuxProtectionCaptures(parent, service)
			switch kind {
			case "parent-only":
				if result != parent || result.standard != nil || result.failure != nil {
					t.Fatal("actual parent owner was hidden by neutral service view")
				}
			case "service-only":
				if result == nil || result.standard != service || result.failure != nil {
					t.Fatal("original service owner was hidden")
				}
			case "proved-empty":
				if result != nil {
					t.Fatal("proved empty owner blocked ordinary preferences")
				}
			default:
				if result == nil || result.failure == nil {
					t.Fatal("competing/unknown ownership became absent")
				}
			}
		})
	}
}
