package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"router-vpn/internal/common"
	"router-vpn/internal/mobilemtu"
	"router-vpn/internal/mobiletor"
)

// This is a Tor child IPC peer, not an ordinary external runtime. Its transfer
// and interface values are explicit synthetic protocol fixtures. They make no
// claim about a physical TUN, Internet PMTU, loss or live Tor performance.
func desktopTorMTUChildFixture(kind, directory string, expected mobiletor.DesktopBridgeMetadata, proof *desktopTorProof, write func(string, any)) func() {
	record := desktopMTURecord{Schema: 1, Session: expected.SessionID, SourceSHA256: expected.SourceSHA256, ConfigSHA256: expected.ConfigSHA256,
		Requested: expected.MTUPolicy == "auto" && !expected.JumboTUN, Status: mobilemtu.Status{Phase: "idle", EffectiveMTU: expected.ConfiguredMTU, Source: "configured-unmeasured", Candidates: []mobilemtu.Candidate{}}}
	write("mtu-status.json", record)
	read := func(name string, value any) bool {
		raw, err := os.ReadFile(filepath.Join(directory, name))
		return err == nil && decodeRelayControlJSON(raw, value) == nil
	}
	remove := func() {
		for _, name := range []string{"mtu-request.json", "mtu-commit.json", "mtu-cancel.json"} {
			_ = os.Remove(filepath.Join(directory, name))
		}
	}
	var revision uint64
	index := proof.InterfaceIndex
	readback := func(mtu int, replace, publish bool) {
		if replace {
			revision++
			index++
		}
		receipt := mobiletor.DesktopBridgeMTUReadback{Generation: record.Generation, RequestID: record.Status.Request, Revision: revision,
			InterfaceName: proof.InterfaceName, InterfaceIndex: index, EffectiveMTU: mtu}
		record.MTUReadback = &receipt
		if publish {
			captured := receipt
			proof.MTUReadback, proof.InterfaceIndex, proof.EffectiveMTU = &captured, index, mtu
		}
	}
	matches := func(control desktopMTUControl) bool {
		return control.Schema == 1 && control.Session == expected.SessionID && control.SourceSHA256 == expected.SourceSHA256 &&
			control.ConfigSHA256 == expected.ConfigSHA256 && control.Generation == record.Generation && control.Request == record.Status.Request
	}
	return func() {
		if !strings.HasPrefix(kind, "tor-mtu-") {
			return
		}
		changed := false
		var request desktopMTURequest
		if !record.Status.Running && read("mtu-request.json", &request) && request.Schema == 1 && request.Session == expected.SessionID &&
			request.SourceSHA256 == expected.SourceSHA256 && request.ConfigSHA256 == expected.ConfigSHA256 && request.Generation == record.Generation+1 {
			record.Generation = request.Generation
			record.RestoredMTU = 0
			record.Status = mobilemtu.Status{Request: request.Request, Running: true, Phase: "measuring", OriginalMTU: proof.EffectiveMTU,
				EffectiveMTU: proof.EffectiveMTU, Source: "unmeasured", PathKey: strings.Repeat("b", 64), Candidates: []mobilemtu.Candidate{}}
			readback(proof.EffectiveMTU, false, true)
			if kind != "tor-mtu-hold" && request.RestoreMTU == 0 {
				record.Status.Candidates = []mobilemtu.Candidate{desktopMTUCandidateFixture(1380)}
				record.WaitingCommit, record.PreparedMTU, record.PreparedPathKey = true, 1380, record.Status.PathKey
				readback(1380, true, true)
			}
			if request.RestoreMTU > 0 {
				// The restored value is proved again but is not a new measured
				// winner. A deliberately missing proof has its own negative case.
				record.WaitingCommit, record.PreparedMTU, record.PreparedPathKey = false, 0, ""
				record.RestoredMTU = request.RestoreMTU
				record.Status.Candidates = []mobilemtu.Candidate{desktopMTUCandidateFixture(request.RestoreMTU)}
				record.Status.Running, record.Status.Complete, record.Status.Restored = false, true, true
				record.Status.Source, record.Status.Phase, record.Status.EffectiveMTU = "restored-captured-system-tun", "restored-captured-mtu", request.RestoreMTU
				readback(request.RestoreMTU, true, kind != "tor-mtu-restore-no-proof")
				remove()
			}
			changed = true
		}
		var cancel, commit desktopMTUControl
		if record.Status.Request != "" && read("mtu-cancel.json", &cancel) && matches(cancel) {
			if !record.Status.Restored || record.Status.Source == "restored-captured-system-tun" {
				readback(record.Status.OriginalMTU, proof.EffectiveMTU != record.Status.OriginalMTU || record.MTUReadback.EffectiveMTU != record.Status.OriginalMTU, true)
			}
			record.WaitingCommit, record.PreparedMTU, record.PreparedPathKey, record.RestoredMTU = false, 0, "", 0
			record.Status.Running, record.Status.Complete, record.Status.Measured, record.Status.Restored = false, true, false, true
			record.Status.Source, record.Status.Phase, record.Status.EffectiveMTU = "restored-unmeasured", "restored", record.Status.OriginalMTU
			remove()
			changed = true
		} else if record.WaitingCommit && kind != "tor-mtu-commit-hold" && read("mtu-commit.json", &commit) && matches(commit) && commit.PathKey == record.PreparedPathKey && commit.MTU == record.PreparedMTU {
			record.Status.Running, record.Status.Complete, record.Status.Measured = false, true, true
			record.Status.Source, record.Status.Phase, record.Status.EffectiveMTU = "measured-tor-system-tun-transfer", "complete", record.PreparedMTU
			record.WaitingCommit, record.PreparedMTU, record.PreparedPathKey = false, 0, ""
			remove()
			changed = true
		}
		if changed {
			write("mtu-status.json", record)
		}
	}
}

func desktopTorPathChildFixture(kind, directory string, expected mobiletor.DesktopBridgeMetadata, write func(string, any)) func() {
	record := desktopPathRecord{desktopPathRequest: desktopPathRequest{Schema: 1, Session: expected.SessionID, SourceSHA256: expected.SourceSHA256, ConfigSHA256: expected.ConfigSHA256}, Complete: true}
	write("path-status.json", record)
	return func() {
		var request desktopPathRequest
		raw, err := os.ReadFile(filepath.Join(directory, "path-request.json"))
		if err != nil || decodeRelayControlJSON(raw, &request) != nil || request.Schema != 1 || request.Session != expected.SessionID ||
			request.SourceSHA256 != expected.SourceSHA256 || request.ConfigSHA256 != expected.ConfigSHA256 || request.Generation != record.Generation+1 {
			return
		}
		record = desktopPathRecord{desktopPathRequest: request, Complete: true, Verified: true, CheckedAt: time.Now().UnixMilli()}
		if kind == fmt.Sprintf("tor-mtu-path-fail-%d", request.Generation) {
			record.Verified, record.CheckedAt = false, 0
		}
		_ = os.Remove(filepath.Join(directory, "path-request.json"))
		write("path-status.json", record)
	}
}

func desktopTorMTUControllerFixture(t *testing.T, kind string) (*app, *desktopNodeLaunch) {
	t.Helper()
	a, launch, _ := desktopTorRunningFixture(t, kind, func(profile *common.RouterProfile) {
		// History is part of the original captured private source. Never edit
		// the active profile after capture merely to manufacture a test baseline.
		profile.EffectiveMTU, profile.EffectiveMTUSource = 1350, "historical-fixture"
		profile.EffectiveMTUPathKey = strings.Repeat("a", 64)
		profile.EffectiveMTUTestedAt = time.Now().Add(-time.Hour).UTC().Format(time.RFC3339Nano)
	})
	if launch.external != nil || launch.tor == nil {
		t.Fatal("Tor MTU fixture manufactured an ordinary external owner")
	}
	a.cfg.ProfilesFile = filepath.Join(t.TempDir(), "profiles.json")
	a.mu.Lock()
	a.state.Connected, a.state.Phase = true, "connected"
	a.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	if _, err := a.waitDesktopTorProof(ctx, launch); err != nil {
		t.Fatal(err)
	}
	a.mu.Lock()
	err := a.persistProfilesLocked()
	captureDesktopMTUBaselineLocked(a, launch)
	a.mu.Unlock()
	if err != nil || desktopMeasurementMTUSession(launch) == nil {
		t.Fatal("Tor connection did not capture its own MTU baseline", err)
	}
	t.Cleanup(func() {
		mtuRetestLocks.Delete(a)
		mtuViewSlots.Delete(a)
		mtuSuspensions.Delete(a)
		speedLabTemporaryOwners.Delete(a)
	})
	return a, launch
}

func desktopTorSavedMTU(t *testing.T, a *app) common.RouterProfile {
	t.Helper()
	a.mu.Lock()
	defer a.mu.Unlock()
	return common.CloneRouterProfile(a.profiles.Profiles[0])
}

func TestDesktopTorSourceIdentityOmitsOnlyDerivedMTUMetadata(t *testing.T) {
	profile, _ := desktopTorPolicyFixture(t)
	before := common.CloneRouterProfile(profile)
	expected := desktopTorSourceIdentityToken(profile)
	derived := common.CloneRouterProfile(profile)
	derived.EffectiveMTU, derived.EffectiveUnderlayPMTU = 1380, 1440
	derived.EffectiveMTUSource, derived.EffectiveMTUTestedAt = "measured-tor-system-tun-transfer", "2026-10-26T00:00:00Z"
	derived.EffectiveMTUPathKey, derived.EffectiveMTUNetworkFingerprint, derived.EffectiveMTUProfileFingerprint = "path", "network", "profile"
	derived.EffectiveMTUMbps, derived.EffectiveMTUMedianRTTMs, derived.EffectiveMTUSuccessRatio = 10, 25, 1
	if desktopTorSourceIdentityToken(derived) != expected || profile.EffectiveMTU != before.EffectiveMTU {
		t.Fatal("derived MTU history changed retained Tor source identity or mutated its profile")
	}
	if asyncMeasurementProfileToken(derived) == asyncMeasurementProfileToken(profile) {
		t.Fatal("Tor-specific projection weakened the global async identity")
	}
	for name, change := range map[string]func(*common.RouterProfile){
		"node":           func(p *common.RouterProfile) { p.ID += "-other" },
		"api-key":        func(p *common.RouterProfile) { p.APIToken += "-other" },
		"bridge-key":     func(p *common.RouterProfile) { p.External.TorBridge.Bridges[0] += " changed-key" },
		"transport":      func(p *common.RouterProfile) { p.External.TorBridge.Transport += "-other" },
		"tor-socks-port": func(p *common.RouterProfile) { p.External.TorBridge.SocksPort++ },
		"dns-mode":       func(p *common.RouterProfile) { p.DNSMode = "home" },
		"dns-host":       func(p *common.RouterProfile) { p.DNSHost = "198.51.100.53" },
		"dns-port":       func(p *common.RouterProfile) { p.DNSPort++ },
		"dns-transport":  func(p *common.RouterProfile) { p.DNSProtocol = "tls" },
		"dns-name":       func(p *common.RouterProfile) { p.DNSServerName = "dns.example.invalid" },
		"dns-path":       func(p *common.RouterProfile) { p.DNSPath = "/other-query" },
		"home-v4":        func(p *common.RouterProfile) { p.AdGuardIPv4 = "192.0.2.53" },
		"home-v6":        func(p *common.RouterProfile) { p.AdGuardIPv6 = "fd00::53" },
		"lan":            func(p *common.RouterProfile) { p.HomeLANAccess = !p.HomeLANAccess },
		"lan-prefix":     func(p *common.RouterProfile) { p.HomeLANCIDRs = append(p.HomeLANCIDRs, "192.0.2.0/24") },
		"ipv6":           func(p *common.RouterProfile) { p.IPv6Mode = "off" },
		"protection":     func(p *common.RouterProfile) { p.KillSwitchPolicy = "off" },
		"mtu-policy":     func(p *common.RouterProfile) { p.MTUPolicy = "manual" },
		"fixed-mtu":      func(p *common.RouterProfile) { p.ManualMTU = 1440 },
		"jumbo":          func(p *common.RouterProfile) { p.JumboTUN = !p.JumboTUN },
		"padding":        func(p *common.RouterProfile) { p.DAITARateKbps++ },
		"entry":          func(p *common.RouterProfile) { p.MultihopEntryID = "other-entry" },
		"execution":      func(p *common.RouterProfile) { p.MultihopExecution = "server" },
		"start-layer":    func(p *common.RouterProfile) { p.StartLayer += "-other" },
		"layers":         func(p *common.RouterProfile) { p.CustomLayers = append(p.CustomLayers, "other") },
		"socks-secret":   func(p *common.RouterProfile) { p.SocksPassword += "-other" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := common.CloneRouterProfile(profile)
			change(&changed)
			if desktopTorSourceIdentityToken(changed) == expected {
				t.Fatal("Tor source identity omitted requested policy/credentials")
			}
		})
	}
}

func TestDesktopTorMTUInitialStatusCannotInventInterfaceReadback(t *testing.T) {
	_, launch := desktopTorMTUControllerFixture(t, "tor-mtu-hold")
	initial, err := readDesktopMTURecord(launch)
	if err != nil || initial.Generation != 0 || initial.MTUReadback != nil || initial.Status.EffectiveMTU != launch.tor.expected.ConfiguredMTU {
		t.Fatal("initial Tor IPC status did not match its configured native reader", err)
	}
	raw, _ := json.Marshal(initial)
	defer func() { _ = atomicWritePrivate(filepath.Join(launch.directory, "mtu-status.json"), raw) }()
	initial.Status.EffectiveMTU += 20
	wrong, _ := json.Marshal(initial)
	if err := atomicWritePrivate(filepath.Join(launch.directory, "mtu-status.json"), wrong); err != nil {
		t.Fatal(err)
	}
	if _, err := readDesktopMTURecord(launch); err == nil {
		t.Fatal("initial idle status invented a Tor interface MTU")
	}
	if _, err := captureDesktopMTURestore(launch); err == nil {
		t.Fatal("restoration captured an initial status value absent from the Tor proof")
	}
}

func TestDesktopTorMTUActualChildCommitAndMonotonicReadback(t *testing.T) {
	a, launch := desktopTorMTUControllerFixture(t, "tor-mtu-winner")
	before := desktopTorSavedMTU(t, a)
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	first, err := a.runDesktopExternalMTU(ctx, launch, true)
	if err != nil || !first.Status.Measured || first.Status.Source != "measured-tor-system-tun-transfer" || first.Status.EffectiveMTU != 1380 || first.MTUReadback == nil {
		t.Fatal("Tor child did not commit its captured MTU receipt", err, first)
	}
	proof, err := a.readDesktopTorProof(launch)
	if err != nil || proof.MTUReadback == nil || *proof.MTUReadback != *first.MTUReadback || proof.Policy.ConfiguredMTU != launch.tor.expected.ConfiguredMTU {
		t.Fatal("Tor MTU winner did not match the retained native reader", err)
	}
	after := desktopTorSavedMTU(t, a)
	if after.EffectiveMTU != 1380 || after.EffectiveMTUSource != first.Status.Source || after.EffectiveMTUProfileFingerprint != launch.tor.mtu.profileToken || after.EffectiveMTUPathKey != first.Status.PathKey ||
		after.EffectiveUnderlayPMTU != 0 || after.EffectiveMTUSuccessRatio != 0 || after.DNSHost != before.DNSHost || after.MTUPolicy != before.MTUPolicy || !slices.Equal(after.External.TorBridge.Bridges, before.External.TorBridge.Bridges) {
		t.Fatal("Tor persistence changed policy/credentials or invented UDP PMTU evidence")
	}
	raw, err := os.ReadFile(a.cfg.ProfilesFile)
	var persisted common.RouterProfileStore
	if err != nil || json.Unmarshal(raw, &persisted) != nil || persisted.Profiles[0].EffectiveMTU != 1380 {
		t.Fatal("Tor MTU returned before durable persistence", err)
	}
	path, err := readDesktopPathRecord(launch)
	if err != nil || path.Generation != 3 || !path.Verified {
		t.Fatal("Tor MTU did not prove save, commit and adoption boundaries", err, path)
	}
	second, err := a.runDesktopExternalMTU(ctx, launch, true)
	if err != nil || second.Generation != first.Generation+1 || second.Status.Request == first.Status.Request || second.MTUReadback == nil || second.MTUReadback.Revision <= first.MTUReadback.Revision {
		t.Fatal("next Tor request reset native reader revision or reused its nonce", err)
	}
	old := proof
	old.HeartbeatAt = time.Now().UnixMilli()
	encoded, _ := json.Marshal(old)
	if _, err := validateDesktopTorProof(encoded, launch.tor, time.Now()); err == nil {
		t.Fatal("an earlier request's reader attested the later Tor operation")
	}
	current, err := a.readDesktopTorProof(launch)
	if err != nil {
		t.Fatal(err)
	}
	currentBytes, _ := json.Marshal(current)
	for _, fault := range []string{"revision-regressed", "same-revision-new-reader", "same-revision-new-mtu", "wrong-request"} {
		var changed desktopTorProof
		_ = json.Unmarshal(currentBytes, &changed)
		changed.HeartbeatAt = time.Now().UnixMilli()
		switch fault {
		case "revision-regressed":
			changed.MTUReadback.Revision--
		case "same-revision-new-reader":
			changed.InterfaceIndex++
			changed.MTUReadback.InterfaceIndex++
		case "same-revision-new-mtu":
			changed.EffectiveMTU++
			changed.MTUReadback.EffectiveMTU++
		case "wrong-request":
			changed.MTUReadback.RequestID = strings.Repeat("f", 32)
		}
		raw, _ := json.Marshal(changed)
		if _, err := validateDesktopTorProof(raw, launch.tor, time.Now()); err == nil {
			t.Fatal("Tor proof accepted an unauthorized reader transition", fault)
		}
	}
}

func TestDesktopTorMTURetestAPIReportsTheVerifiedTorTransfer(t *testing.T) {
	a, launch := desktopTorMTUControllerFixture(t, "tor-mtu-winner")
	id := strings.Repeat("c", 32)
	body := fmt.Sprintf(`{"request_id":%q,"session_id":%q,"profile_id":%q}`, id, launch.tor.expected.SessionID, launch.profileID)
	response := httptest.NewRecorder()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	a.retestMTU(response, httptest.NewRequest(http.MethodPost, "/api/mtu/retest", strings.NewReader(body)).WithContext(ctx))
	var result struct {
		OK           bool             `json:"ok"`
		EffectiveMTU int              `json:"effective_mtu"`
		Source       string           `json:"effective_mtu_source"`
		Status       mobilemtu.Status `json:"result"`
		Note         string           `json:"note"`
	}
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &result) != nil || !result.OK ||
		result.EffectiveMTU != 1380 || result.Source != "measured-tor-system-tun-transfer" || result.Status.Request != id ||
		!result.Status.Complete || !result.Status.Measured || result.Status.Source != result.Source ||
		!strings.Contains(result.Note, "Tor HTTPS response time") || !strings.Contains(result.Note, "not an authenticated UDP path-MTU measurement") {
		t.Fatal("Tor Retest API lost its captured transfer identity or mislabeled its result", response.Code, response.Body.String())
	}
	proof, err := a.readDesktopTorProof(launch)
	if err != nil || proof.MTUReadback == nil || proof.MTUReadback.RequestID != id || proof.EffectiveMTU != result.EffectiveMTU ||
		desktopTorSavedMTU(t, a).EffectiveMTU != result.EffectiveMTU {
		t.Fatal("Tor Retest API returned before live reader proof and durable persistence", err)
	}
}

func TestDesktopTorMTURetestAndExactCancelAPI(t *testing.T) {
	for _, kind := range []string{"tor-mtu-hold", "tor-mtu-commit-hold"} {
		t.Run(kind, func(t *testing.T) {
			a, launch := desktopTorMTUControllerFixture(t, kind)
			id := strings.Repeat("c", 32)
			body := fmt.Sprintf(`{"request_id":%q,"session_id":%q,"profile_id":%q}`, id, launch.tor.expected.SessionID, launch.profileID)
			response := httptest.NewRecorder()
			done := make(chan struct{})
			ctx, stop := context.WithCancel(context.Background())
			defer stop()
			go func() {
				defer close(done)
				a.retestMTU(response, httptest.NewRequest(http.MethodPost, "/api/mtu/retest", strings.NewReader(body)).WithContext(ctx))
			}()
			record := desktopMTUWaitRecord(t, launch, func(r desktopMTURecord) bool { return r.Status.Request == id && r.Status.Running })
			progress := httptest.NewRecorder()
			a.desktopMTUStatus(progress, httptest.NewRequest(http.MethodGet, "/api/mtu/status?request_id="+id+"&session_id="+launch.tor.expected.SessionID, nil))
			var progressView struct {
				Status mobilemtu.Status `json:"status"`
			}
			if progress.Code != http.StatusOK || json.Unmarshal(progress.Body.Bytes(), &progressView) != nil || !progressView.Status.Running || progressView.Status.Request != id {
				t.Fatal("Tor progress view escaped its captured operation", progress.Code, progress.Body.String())
			}
			if kind == "tor-mtu-commit-hold" {
				deadline := time.Now().Add(5 * time.Second)
				for {
					if _, err := readDesktopRuntimeFile(launch, "mtu-commit.json", 4096); err == nil {
						break
					}
					if time.Now().After(deadline) {
						t.Fatal("Tor provisional winner never reached commit boundary")
					}
					time.Sleep(10 * time.Millisecond)
				}
			}
			for _, request := range []string{strings.Replace(body, id, strings.Repeat("f", 32), 1), strings.Replace(body, launch.tor.expected.SessionID, strings.Repeat("e", 32), 1), body} {
				cancelled := httptest.NewRecorder()
				a.cancelDesktopMTURoute(cancelled, httptest.NewRequest(http.MethodPost, "/api/mtu/cancel", strings.NewReader(request)))
				want := http.StatusConflict
				if request == body {
					want = http.StatusOK
				}
				if cancelled.Code != want {
					t.Fatal("Tor Cancel lost captured API ownership", cancelled.Code, cancelled.Body.String())
				}
			}
			select {
			case <-done:
				if response.Code != http.StatusConflict {
					t.Fatal("cancelled Tor Retest reported success", response.Code, response.Body.String())
				}
			case <-time.After(5 * time.Second):
				t.Fatal("Tor Retest cancellation did not join rollback")
			}
			result := desktopMTUWaitRecord(t, launch, func(r desktopMTURecord) bool { return r.Status.Request == id && r.Status.Complete && r.Status.Restored })
			proof, err := a.readDesktopTorProof(launch)
			if err != nil || proof.MTUReadback == nil || *proof.MTUReadback != *result.MTUReadback || result.Status.EffectiveMTU != launch.tor.expected.ConfiguredMTU || result.Status.Measured ||
				kind == "tor-mtu-commit-hold" && result.MTUReadback.Revision <= record.MTUReadback.Revision {
				t.Fatal("cancel did not retain the exact rollback reader", err)
			}
			if saved := desktopTorSavedMTU(t, a); saved.EffectiveMTU != 1350 || saved.EffectiveMTUSource != "historical-fixture" {
				t.Fatal("cancel left a provisional Tor measurement saved")
			}
			progress = httptest.NewRecorder()
			a.desktopMTUStatus(progress, httptest.NewRequest(http.MethodGet, "/api/mtu/status?request_id="+id+"&session_id="+launch.tor.expected.SessionID, nil))
			if progress.Code != http.StatusOK || json.Unmarshal(progress.Body.Bytes(), &progressView) != nil || progressView.Status.Running || !progressView.Status.Complete || !progressView.Status.Restored || progressView.Status.Request != id {
				t.Fatal("Tor terminal view acknowledged cancellation before rollback", progress.Code, progress.Body.String())
			}
		})
	}
}

func TestDesktopTorMTUAutomaticUsesOwnNativeMailbox(t *testing.T) {
	a, launch := desktopTorMTUControllerFixture(t, "tor-mtu-hold")
	a.startDesktopExternalAutomaticMTU(launch)
	record := desktopMTUWaitRecord(t, launch, func(r desktopMTURecord) bool { return r.Status.Running })
	raw, err := readDesktopRuntimeFile(launch, "mtu-request.json", 4096)
	var request desktopMTURequest
	if err != nil || json.Unmarshal(raw, &request) != nil || request.Force || request.Request != record.Status.Request || request.SourceSHA256 != launch.tor.expected.SourceSHA256 || launch.external != nil {
		t.Fatal("Tor Auto MTU bypassed its real native request identity", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	release, err := a.holdDesktopMTUForMeasurement(ctx)
	if err != nil {
		t.Fatal("Auto MTU did not drain before a captured measurement", err)
	}
	defer func() {
		// The fixture ends this connection rather than starting new automatic
		// work after its final measurement hold is released.
		a.mu.Lock()
		a.state.Connected = false
		a.mu.Unlock()
		release()
	}()
	result := desktopMTUWaitRecord(t, launch, func(r desktopMTURecord) bool { return r.Status.Complete && r.Status.Restored })
	if result.Status.EffectiveMTU != launch.tor.expected.ConfiguredMTU || desktopTorSavedMTU(t, a).EffectiveMTU != 1350 {
		t.Fatal("Auto cancellation changed saved/live baseline")
	}
}

func TestDesktopTorMTUFreshPathFailureCannotPersist(t *testing.T) {
	for stage := 1; stage <= 3; stage++ {
		t.Run(fmt.Sprint(stage), func(t *testing.T) {
			a, launch := desktopTorMTUControllerFixture(t, fmt.Sprintf("tor-mtu-path-fail-%d", stage))
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if _, err := a.runDesktopExternalMTU(ctx, launch, true); err == nil {
				t.Fatal("healthy Tor heartbeat replaced a failed fresh path proof")
			}
			result := desktopMTUWaitRecord(t, launch, func(r desktopMTURecord) bool { return r.Status.Complete && r.Status.Restored })
			if result.Status.EffectiveMTU != launch.tor.expected.ConfiguredMTU || desktopTorSavedMTU(t, a).EffectiveMTU != 1350 {
				t.Fatal("failed Tor path retained its provisional winner")
			}
			path, err := readDesktopPathRecord(launch)
			if err != nil || path.Generation != uint64(stage) || path.Verified {
				t.Fatal("test failed before the intended fresh Tor path boundary", stage, path, err)
			}
		})
	}
}

func TestDesktopTorMTUFailedPersistenceRollsBackNativeReader(t *testing.T) {
	a, launch := desktopTorMTUControllerFixture(t, "tor-mtu-winner")
	if err := os.Remove(a.cfg.ProfilesFile); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(a.cfg.ProfilesFile, 0700); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := a.runDesktopExternalMTU(ctx, launch, true); err == nil {
		t.Fatal("failed durable save reported successful Tor MTU")
	}
	record := desktopMTUWaitRecord(t, launch, func(r desktopMTURecord) bool { return r.Status.Complete && r.Status.Restored })
	if record.Status.EffectiveMTU != launch.tor.expected.ConfiguredMTU || desktopTorSavedMTU(t, a).EffectiveMTU != 1350 {
		t.Fatal("failed save retained provisional Tor MTU")
	}
	if _, err := readDesktopRuntimeFile(launch, "mtu-commit.json", 4096); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("failed save sent native commit", err)
	}
}

func TestDesktopTorMTURetiredSourceCannotAdopt(t *testing.T) {
	for _, field := range []string{"dns", "bridge", "speed-lab"} {
		t.Run(field, func(t *testing.T) {
			a, launch := desktopTorMTUControllerFixture(t, "tor-mtu-hold")
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() { _, err := a.runDesktopExternalMTU(ctx, launch, true); done <- err }()
			desktopMTUWaitRecord(t, launch, func(r desktopMTURecord) bool { return r.Status.Running })
			a.mu.Lock()
			switch field {
			case "dns":
				a.profiles.Profiles[0].DNSPort++
			case "bridge":
				a.profiles.Profiles[0].External.TorBridge.Bridges[0] += " changed-owner"
			case "speed-lab":
				speedLabTemporaryOwners.Store(a, &speedLabTemporaryOwner{})
			}
			a.mu.Unlock()
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("retired Tor profile accepted old MTU")
				}
			case <-time.After(5 * time.Second):
				t.Fatal("retired Tor measurement did not finish")
			}
			if desktopTorSavedMTU(t, a).EffectiveMTU != 1350 {
				t.Fatal("retired source installed a measured MTU")
			}
		})
	}
}

func TestDesktopTorMTURestoreRequiresMatchingLiveReadback(t *testing.T) {
	for _, kind := range []string{"tor-mtu-restore", "tor-mtu-restore-no-proof"} {
		t.Run(kind, func(t *testing.T) {
			a, launch := desktopTorMTUControllerFixture(t, kind)
			launch.tor.mtu.restoreMTU = 1400
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			err := a.restoreDesktopCapturedMTU(ctx, launch)
			if kind == "tor-mtu-restore-no-proof" {
				if err == nil {
					t.Fatal("status-only restored MTU replaced the actual live Tor reader")
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				value, err := captureDesktopMTURestore(launch)
				if err != nil || value != 1400 || launch.tor.mtu.restoreMTU != 0 {
					t.Fatal("captured Tor MTU was not restored", value, err)
				}
				proof, err := a.readDesktopTorProof(launch)
				if err != nil || proof.EffectiveMTU != 1400 {
					t.Fatal("restore returned without exact Tor reader", err)
				}
			}
			if desktopTorSavedMTU(t, a).EffectiveMTU != 1350 {
				t.Fatal("temporary Tor restoration rewrote saved measurement")
			}
		})
	}
}

func TestDesktopTorMTUAlreadyEqualRestoreRequiresTheSameReader(t *testing.T) {
	for _, forged := range []bool{false, true} {
		t.Run(fmt.Sprint(forged), func(t *testing.T) {
			a, launch := desktopTorMTUControllerFixture(t, "tor-mtu-winner")
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			record, err := a.runDesktopExternalMTU(ctx, launch, true)
			if err != nil {
				t.Fatal(err)
			}
			original, _ := json.Marshal(record)
			defer func() { _ = atomicWritePrivate(filepath.Join(launch.directory, "mtu-status.json"), original) }()
			launch.tor.mtu.restoreMTU = record.Status.EffectiveMTU
			if forged {
				record.MTUReadback.Revision++
				record.MTUReadback.InterfaceIndex++
				raw, _ := json.Marshal(record)
				if err := atomicWritePrivate(filepath.Join(launch.directory, "mtu-status.json"), raw); err != nil {
					t.Fatal(err)
				}
				if _, err := captureDesktopMTURestore(launch); err == nil {
					t.Fatal("snapshot trusted a status-only replacement reader")
				}
			}
			err = a.restoreDesktopCapturedMTU(ctx, launch)
			if forged && err == nil {
				t.Fatal("already-equal restoration accepted a different live reader")
			}
			if !forged && (err != nil || launch.tor.mtu.restoreMTU != 0) {
				t.Fatal("already-equal live Tor reader was not retained", err)
			}
		})
	}
}

func TestDesktopTorMTURejectsWrongReceiptAndMeasurementLabels(t *testing.T) {
	a, launch := desktopTorMTUControllerFixture(t, "tor-mtu-winner")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	good, err := a.runDesktopExternalMTU(ctx, launch, true)
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(good)
	defer func() { _ = atomicWritePrivate(filepath.Join(launch.directory, "mtu-status.json"), encoded) }()
	for _, fault := range []string{"source", "config", "session", "request", "generation", "missing-readback", "same-revision-other-reader", "wrong-mtu", "public-source", "icmp", "false-throughput", "invented-packet-loss"} {
		t.Run(fault, func(t *testing.T) {
			var bad desktopMTURecord
			_ = json.Unmarshal(encoded, &bad)
			switch fault {
			case "source":
				bad.SourceSHA256 = strings.Repeat("f", 64)
			case "config":
				bad.ConfigSHA256 = strings.Repeat("f", 64)
			case "session":
				bad.Session = strings.Repeat("f", 32)
			case "request":
				bad.MTUReadback.RequestID = strings.Repeat("f", 32)
			case "generation":
				bad.MTUReadback.Generation++
			case "missing-readback":
				bad.MTUReadback = nil
			case "same-revision-other-reader":
				bad.MTUReadback.InterfaceIndex++
			case "wrong-mtu":
				bad.MTUReadback.EffectiveMTU++
			case "public-source":
				bad.Status.Source = "measured-public-system-tun-transfer"
			case "icmp":
				bad.Status.Candidates[0].LatencyKind = "icmp"
			case "false-throughput":
				bad.Status.Candidates[0].Download.Mbps *= 2
			case "invented-packet-loss":
				bad.Status.Candidates[0].PacketsSent = 50
			}
			raw, _ := json.Marshal(bad)
			if err := atomicWritePrivate(filepath.Join(launch.directory, "mtu-status.json"), raw); err != nil {
				t.Fatal(err)
			}
			if _, err := readDesktopMTURecord(launch); err == nil {
				t.Fatal("actual Tor mailbox reader accepted false authority/evidence", fault)
			}
		})
	}
}
