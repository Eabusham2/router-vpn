//go:build go1.25

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"router-vpn/internal/mobilemtu"
)

func desktopImportedMTUPolicyFixture(t *testing.T, protocol string, configure func(*multihopSelection)) *desktopImportedOwnedFixture {
	t.Helper()
	f := newDesktopImportedOwnedFixture(t, protocol, "reality-vision", "always", configure)
	f.stage(t)
	f.publish(t)
	if err := startDesktopOwnedImportedLaunch(f.operation, f.operation, f.a, f.launch); err != nil {
		t.Fatal(err)
	}
	f.a.mu.Lock()
	f.a.state.Connected, f.a.state.Phase = true, "connected"
	f.a.mu.Unlock()
	t.Cleanup(func() {
		desktopImportedMTUUIs.Delete(f.a)
		routerNodeAutomaticMTUs.Delete(f.a)
		mtuViewSlots.Delete(f.a)
		mtuRetestLocks.Delete(f.a)
	})
	return f
}

func TestDesktopImportedMTUMergedPolicyControlsAutoRetestAndStatus(t *testing.T) {
	for _, scenario := range []string{"entry-fixed", "entry-jumbo", "final-fixed", "compatible-auto", "packet-entry-fixed"} {
		t.Run(scenario, func(t *testing.T) {
			protocol := "shadowsocks"
			if scenario == "packet-entry-fixed" {
				protocol = "wireguard"
			}
			f := desktopImportedMTUPolicyFixture(t, protocol, func(selection *multihopSelection) {
				switch scenario {
				case "entry-fixed", "packet-entry-fixed":
					selection.Entry.MTUPolicy, selection.Entry.ManualMTU = "manual", 1400
				case "entry-jumbo":
					selection.Entry.JumboTUN = true
				case "final-fixed":
					selection.Exit.MTUPolicy, selection.Exit.ManualMTU = "manual", 1392
				}
			})
			before := cloneRouterProfileStore(f.a.profiles)
			automatic := scenario == "compatible-auto" || scenario == "packet-entry-fixed"
			_, policy, err := readDesktopImportedMTUPolicyContext(f.operation, f.selection)
			if err != nil || (policy.Automatic && !policy.Jumbo) != automatic || policy.Jumbo != (scenario == "entry-jumbo") {
				t.Fatal("resolved shared-TUN policy lost an original entry or final constraint", policy, err)
			}
			if policy.ID != f.selection.Exit.ID || policy.Proof != f.selection.Exit.NodeProofID || policy.API != f.selection.Exit.RouterAPI || policy.Token != f.selection.Exit.APIToken {
				t.Fatal("merged MTU policy borrowed entry credentials or changed paired final authority")
			}
			runtime, handled, err := desktopImportedMTURuntime(f.operation, f.a)
			if err != nil || !handled || runtime == nil {
				t.Fatal("policy fixture lost its actual connected controller", err)
			}
			u, err := getDesktopImportedMTUUI(f.operation, f.a, runtime)
			if automatic {
				if err != nil || u == nil || !u.controller.Requested() || u.owner.policy != policy {
					t.Fatal("compatible Auto did not reach the actual shared controller", err)
				}
			} else if err == nil || u != nil {
				t.Fatal("Fixed or Jumbo entered the desktop MTU optimizer", err)
			}

			statusResponse := httptest.NewRecorder()
			f.a.desktopMTUStatus(statusResponse, httptest.NewRequest(http.MethodGet, "/api/mtu/status", nil).WithContext(f.operation))
			var status struct {
				Allowed bool             `json:"optimization_allowed"`
				Profile string           `json:"profile_id"`
				Session string           `json:"session_id"`
				Status  mobilemtu.Status `json:"status"`
			}
			live, liveErr := readDesktopNodeMTUContext(f.operation, f.launch)
			if statusResponse.Code != http.StatusOK || json.Unmarshal(statusResponse.Body.Bytes(), &status) != nil || liveErr != nil ||
				status.Allowed != automatic || status.Profile != policy.ID || status.Session != f.launch.mtuSession ||
				status.Status.Measured || status.Status.EffectiveMTU != live.MTU {
				t.Fatal("public status advertised another policy, saved measurement or native reader", statusResponse.Body.String(), liveErr)
			}
			if scenario == "entry-fixed" && live.MTU != 1400 || scenario == "entry-jumbo" && live.MTU != 9000 || scenario == "final-fixed" && live.MTU != 1392 {
				t.Fatal("compiled native TUN did not retain its resolved fixed or Jumbo value", live.MTU)
			}

			// Exercise the real Auto admission with its already-waiting original
			// worker. Only a compatible policy may request that worker's resume;
			// no additional native or network worker is started by this witness.
			queued := &routerNodeAutomaticMTU{command: f.launch.command, waiting: true}
			routerNodeAutomaticMTUs.Store(f.a, queued)
			if !f.a.startDesktopImportedAutomaticMTU() || queued.resume != automatic {
				t.Fatal("Auto ignored the resolved imported policy", queued.resume, automatic)
			}
			routerNodeAutomaticMTUs.Delete(f.a)

			request := mtuViewRequest{Request: strings.Repeat("b", 32), Session: f.launch.mtuSession, Profile: policy.ID}
			raw, _ := json.Marshal(request)
			if automatic {
				desktopImportedMTUPolicyRetestAdmission(t, f, u, raw)
			} else {
				response := httptest.NewRecorder()
				f.a.retestMTU(response, httptest.NewRequest(http.MethodPost, "/api/mtu/retest", bytes.NewReader(raw)).WithContext(f.operation))
				if response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), "captured entry and final") {
					t.Fatal("public Retest did not reject the original shared Fixed or Jumbo policy", response.Code, response.Body.String())
				}
				if _, exists := mtuViewSlots.Load(f.a); exists {
					t.Fatal("rejected policy acquired an MTU request owner")
				}
			}
			if !reflect.DeepEqual(before, f.a.profiles) || f.starts != 1 {
				t.Fatal("MTU policy admission rewrote original profiles or started a replacement child")
			}
		})
	}
}

func desktopImportedMTUPolicyRetestAdmission(t *testing.T, f *desktopImportedOwnedFixture, u *desktopImportedMTUUI, raw []byte) {
	t.Helper()
	entered := make(chan struct{})
	var once sync.Once
	original := u.owner.current
	u.owner.current = func(ctx context.Context) error {
		if err := original(ctx); err != nil {
			return err
		}
		cleanup, _ := mobilemtu.OperationCleanupOnly(ctx)
		if mobilemtu.SameOperationContext(ctx, ctx) && !cleanup {
			once.Do(func() { close(entered) })
			<-ctx.Done()
			return ctx.Err()
		}
		return nil
	}
	defer func() { u.owner.current = original }()
	ctx, cancel := context.WithTimeout(f.operation, 10*time.Second)
	defer cancel()
	response := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		defer close(done)
		f.a.retestMTU(response, httptest.NewRequest(http.MethodPost, "/api/mtu/retest", bytes.NewReader(raw)).WithContext(ctx))
	}()
	select {
	case <-entered:
	case <-done:
		t.Fatal("compatible public Retest did not enter its real original-controller admission", response.Code, response.Body.String())
	case <-ctx.Done():
		<-done
		t.Fatal("compatible public Retest did not reach its bounded admission")
	}
	cancelResponse := httptest.NewRecorder()
	f.a.cancelDesktopMTURoute(cancelResponse, httptest.NewRequest(http.MethodPost, "/api/mtu/cancel", bytes.NewReader(raw)).WithContext(f.operation))
	if cancelResponse.Code != http.StatusOK || !strings.Contains(cancelResponse.Body.String(), `"phase":"canceling"`) {
		cancel()
		<-done
		t.Fatal("entered compatible Retest lost its original Cancel owner", cancelResponse.Body.String())
	}
	<-done
	if response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), "context canceled") || u.owner.mailboxHeld || u.owner.committed.Load() {
		t.Fatal("cancelled pre-mutation Retest published a result or retained a lease", response.Code, response.Body.String())
	}
}

func TestDesktopImportedMTUMergedPolicyRefusesChangedOriginalSource(t *testing.T) {
	for _, scenario := range []string{"envelope", "resealed-source", "resealed-graph", "entry-policy", "final-authority"} {
		t.Run(scenario, func(t *testing.T) {
			f := desktopImportedMTUPolicyFixture(t, "shadowsocks", func(*multihopSelection) {})
			selection := f.selection
			switch scenario {
			case "envelope":
				selection.Native.importedInput += " "
			case "resealed-source":
				selection.Native.importedOriginalSource = strings.Repeat("0", 64)
				selection.Native.source = selection.Native.importedCaptureDigest()
			case "resealed-graph":
				selection.Native.configs[selection.ExitMode] += " "
				selection.Native.source = selection.Native.importedCaptureDigest()
			case "entry-policy":
				selection.Entry.MTUPolicy, selection.Entry.ManualMTU = "manual", 1400
			case "final-authority":
				selection.Exit.APIToken = "another paired final credential"
			}
			if raw, _, err := readDesktopImportedMTUPolicyContext(f.operation, selection); err == nil || raw != "" {
				t.Fatal("changed original source supplied a replacement MTU policy", scenario, err)
			}
		})
	}
}
