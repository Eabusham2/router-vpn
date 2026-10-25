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
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"router-vpn/internal/common"
	"router-vpn/internal/dnsmeasure"
	"router-vpn/internal/mobilemultihop"
)

// This real child exchanges explicit IPC fixture records, not network results.
// The native template suite separately runs the actual DNS service/query code.
func desktopDNSChildFixture(kind, directory string, expected mobilemultihop.ExternalProofResult, write func(string, any)) func() {
	if !strings.HasPrefix(kind, "dns-") {
		return func() {}
	}
	record := desktopDNSNativeRecord{desktopDNSNativeRequest: desktopDNSNativeRequest{Schema: 1, Session: expected.SessionID, SourceSHA256: expected.SourceSHA256, ConfigSHA256: expected.ConfigSHA256}, Status: dnsmeasure.Status{Schema: 1, NodeID: expected.ExitID, SessionID: expected.SessionID, Stage: "idle", Complete: true, Drained: true, Results: []dnsmeasure.Result{}}}
	write("dns-status.json", record)
	read := func(name string, target any) bool {
		raw, err := os.ReadFile(filepath.Join(directory, name))
		return err == nil && decodeRelayControlJSON(raw, target) == nil
	}
	remove := func() {
		_ = os.Remove(filepath.Join(directory, "dns-request.json"))
		_ = os.Remove(filepath.Join(directory, "dns-cancel.json"))
	}
	return func() {
		var request desktopDNSNativeRequest
		if record.Status.Complete && record.Status.Drained && read("dns-request.json", &request) && request.Schema == 1 && request.Session == expected.SessionID && request.SourceSHA256 == expected.SourceSHA256 && request.ConfigSHA256 == expected.ConfigSHA256 && request.Generation == record.Generation+1 {
			record = desktopDNSNativeRecord{desktopDNSNativeRequest: request, Status: dnsmeasure.Status{Schema: 1, NodeID: expected.ExitID, SessionID: expected.SessionID, Request: request.Request, PublicTransport: request.Transport, Stage: "measuring", Results: []dnsmeasure.Result{}}}
		}
		if record.Generation == 0 {
			return
		}
		var cancel desktopDNSNativeRequest
		if read("dns-cancel.json", &cancel) && cancel == record.desktopDNSNativeRequest {
			record.Status.Stage, record.Status.Failure, record.Status.Complete, record.Status.Results = "cancelled", "fixture cancellation", true, []dnsmeasure.Result{}
			_, released := os.Stat(filepath.Join(directory, "dns-drain-release.fixture"))
			record.Status.Drained = kind != "dns-cancel-delay" && kind != "dns-read-fail" || released == nil
			if record.Status.Drained {
				remove()
			}
		} else if !record.Status.Complete && kind != "dns-hold" && kind != "dns-cancel-delay" && kind != "dns-read-fail" {
			source, _ := os.ReadFile(filepath.Join(directory, "source.json"))
			capture, _ := os.ReadFile(filepath.Join(directory, "capture.json"))
			policy, err := mobilemultihop.NewExternalPolicy(string(source), string(capture))
			if err != nil {
				os.Exit(93)
			}
			var metadata struct {
				Protocol string `json:"dns_protocol"`
				Server   string `json:"dns_server"`
				Port     int    `json:"dns_port"`
				Name     string `json:"dns_server_name"`
				Path     string `json:"dns_path"`
				Detour   string `json:"dns_detour"`
			}
			_ = json.Unmarshal([]byte(policy.Metadata()), &metadata)
			selected := dnsmeasure.Endpoint{ID: "selected", Name: "Selected DNS", Kind: "selected", Address: metadata.Server, Port: metadata.Port, Transport: metadata.Protocol, ServerName: metadata.Name, Path: metadata.Path, Route: metadata.Detour, RouteLabel: "Selected DNS via " + metadata.Detour}
			for i, endpoint := range append([]dnsmeasure.Endpoint{selected}, dnsmeasure.PublicEndpoints(record.Transport, "Current external exit")...) {
				median := float64(i + 1)
				row := dnsmeasure.Result{Endpoint: endpoint, Samples: 3, Ready: true, Median: &median}
				if strings.Contains(endpoint.ID, "6") {
					row.Samples, row.Failed, row.Ready, row.Median, row.Failure = 0, 3, false, nil, "IPv6 disabled fixture"
				}
				record.Status.Results = append(record.Status.Results, row)
			}
			if kind == "dns-wrong-transport" {
				record.Status.Results[1].Transport = "udp"
			}
			record.Status.Stage, record.Status.Complete, record.Status.Drained = "complete", true, true
			remove()
		}
		published := record
		if kind == "dns-read-fail" && !record.Status.Drained {
			published.Session = "different-native-owner"
		}
		write("dns-status.json", published)
	}
}

func desktopDNSControllerFixture(t *testing.T, kind string) (*app, *desktopNodeLaunch) {
	t.Helper()
	a, launch := desktopMTUControllerFixture(t, kind)
	launch.external.mtu.mu.Lock()
	launch.external.mtu.automatic = true // this fixture has already completed its automatic MTU pass
	launch.external.mtu.mu.Unlock()
	t.Cleanup(func() {
		a.mu.Lock()
		a.closing = true
		a.mu.Unlock()
		invalidateDesktopDNSResults(a)
	})
	return a, launch
}

func desktopDNSHTTP(t *testing.T, a *app, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var data []byte
	var err error
	if body != nil {
		data, err = json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
	}
	mux := http.NewServeMux()
	registerDNSPolicyRoute(mux, a)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest(method, path, bytes.NewReader(data)))
	return w
}

func desktopDNSCaptureForTest(t *testing.T, a *app) desktopDNSView {
	t.Helper()
	w := desktopDNSHTTP(t, a, http.MethodGet, "/api/dns/measurement", nil)
	var view desktopDNSView
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &view) != nil || view.Status.Stage != "idle" || !view.Status.Drained || view.SessionID == "" || view.ProfileToken == "" {
		t.Fatal("capture", w.Code, w.Body.String())
	}
	return view
}

func desktopDNSStartForTest(t *testing.T, a *app, transport string) (*desktopDNSOperation, desktopDNSRequest) {
	t.Helper()
	view := desktopDNSCaptureForTest(t, a)
	id, err := randomHex(16)
	if err != nil {
		t.Fatal(err)
	}
	request := desktopDNSRequest{ProfileID: view.ProfileID, ProfileToken: view.ProfileToken, SessionID: view.SessionID, Request: id, Transport: transport}
	w := desktopDNSHTTP(t, a, http.MethodPost, "/api/dns/measurement", request)
	if w.Code != http.StatusAccepted {
		t.Fatal("start", w.Code, w.Body.String())
	}
	operation, err := a.desktopDNSOperationFor(id)
	if err != nil {
		t.Fatal(err)
	}
	return operation, request
}

func desktopDNSWaitForTest(t *testing.T, a *app, operation *desktopDNSOperation, condition func(desktopDNSView) bool) desktopDNSView {
	t.Helper()
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		view := operation.view(a)
		if condition(view) {
			return view
		}
		select {
		case <-deadline.C:
			t.Fatal("DNS operation state", view.Status)
		case <-tick.C:
		}
	}
}

func TestDesktopDNSNativeTypedDraftKeepsTransportAndSurvivesExplicitDisconnect(t *testing.T) {
	for _, transport := range []string{"tcp", "tls", "https"} {
		t.Run(transport, func(t *testing.T) {
			a, launch := desktopDNSControllerFixture(t, "dns-winner")
			before := cloneRouterProfileStore(a.profiles)
			operation, request := desktopDNSStartForTest(t, a, transport)
			view := desktopDNSWaitForTest(t, a, operation, func(v desktopDNSView) bool { return v.Status.Complete && v.Status.Drained })
			if view.Status.Stage != "complete" || len(view.Status.Results) != 13 || view.ExpiresInMS <= 0 {
				t.Fatal("typed results", view)
			}
			<-operation.done
			a.mu.Lock()
			after := cloneRouterProfileStore(a.profiles)
			a.mu.Unlock()
			if !reflect.DeepEqual(before, after) {
				t.Fatal("measurement silently changed the selected resolver, credentials, or legacy Fastest fields")
			}
			request.Transport, request.ResultID = "", "fastest"
			selected := desktopDNSHTTP(t, a, http.MethodPost, "/api/dns/measurement/select", request)
			var payload struct {
				Draft   dnsPolicyRequest `json:"draft"`
				Expires int64            `json:"expires_in_ms"`
			}
			if selected.Code != http.StatusOK || json.Unmarshal(selected.Body.Bytes(), &payload) != nil || payload.Draft.ResultID != "cf4a" || payload.Draft.Protocol != transport {
				t.Fatal("draft", selected.Code, selected.Body.String())
			}
			if w := desktopDNSHTTP(t, a, http.MethodPost, "/api/dns/policy", payload.Draft); w.Code != http.StatusConflict {
				t.Fatal("measured draft changed active DNS", w.Code)
			}
			if err := prepareDesktopExternalStop(a, launch.command); err != nil {
				t.Fatal(err)
			}
			select {
			case <-desktopExternalProcessDone(launch):
			case <-time.After(3 * time.Second):
				t.Fatal("fixture native stop did not drain")
			}
			a.mu.Lock()
			a.cmd = nil
			a.state = state{Mode: "off", Phase: "off"}
			a.mu.Unlock()
			w := desktopDNSHTTP(t, a, http.MethodPost, "/api/dns/policy", payload.Draft)
			if w.Code != http.StatusOK {
				t.Fatal("explicit disconnect lost exact current draft", w.Code, w.Body.String())
			}
			a.mu.Lock()
			saved := cloneRouterProfile(a.profiles.Profiles[0])
			a.mu.Unlock()
			if saved.DNSProtocol != transport || saved.DNSPort != payload.Draft.Port || saved.DNSServerName != payload.Draft.ServerName || saved.DNSPath != payload.Draft.Path || saved.FastestDNSHost != "" || saved.External.Hysteria2.Password != before.Profiles[0].External.Hysteria2.Password {
				t.Fatal("typed DNS receipt was reinterpreted or private source changed")
			}
		})
	}
}

func TestDesktopDNSCancelBeforeStartWinsTransactionAndLateNonce(t *testing.T) {
	a, launch := desktopDNSControllerFixture(t, "dns-hold")
	view := desktopDNSCaptureForTest(t, a)
	request := desktopDNSRequest{ProfileID: view.ProfileID, ProfileToken: view.ProfileToken, SessionID: view.SessionID, Request: strings.Repeat("e", 32)}
	// Cancel is admitted even while Start's connection/settings transaction is
	// still held; it does not wait for that queued POST to reach native work.
	a.operationMu.Lock()
	w := desktopDNSHTTP(t, a, http.MethodPost, "/api/dns/measurement/cancel", request)
	a.operationMu.Unlock()
	var receipt desktopDNSView
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &receipt) != nil || !receipt.Status.Drained {
		t.Fatal("queued cancel", w.Code, w.Body.String())
	}
	request.Transport = "https"
	if w = desktopDNSHTTP(t, a, http.MethodPost, "/api/dns/measurement", request); w.Code != http.StatusConflict {
		t.Fatal("cancelled queued Start reopened", w.Code)
	}
	if record, err := readDesktopDNSRecord(launch); err != nil || record.Generation != 0 {
		t.Fatal("cancel-before-start opened native work", record, err)
	}
}

func TestDesktopDNSCancelAndReadFailureRetainMTUHoldUntilExactNativeDrain(t *testing.T) {
	for _, kind := range []string{"dns-cancel-delay", "dns-read-fail"} {
		t.Run(kind, func(t *testing.T) {
			a, launch := desktopDNSControllerFixture(t, kind)
			operation, request := desktopDNSStartForTest(t, a, "https")
			if kind == "dns-cancel-delay" {
				desktopDNSWaitForTest(t, a, operation, func(v desktopDNSView) bool { return v.Status.Stage == "measuring" })
				wrong := request
				wrong.Transport = ""
				wrong.SessionID = strings.Repeat("f", 32)
				if w := desktopDNSHTTP(t, a, http.MethodPost, "/api/dns/measurement/cancel", wrong); w.Code != http.StatusConflict {
					t.Fatal("foreign cancel accepted")
				}
				request.Transport = ""
				if w := desktopDNSHTTP(t, a, http.MethodPost, "/api/dns/measurement/cancel", request); w.Code != http.StatusAccepted {
					t.Fatal("cancel", w.Code, w.Body.String())
				}
			}
			view := desktopDNSWaitForTest(t, a, operation, func(v desktopDNSView) bool { return v.Status.Stage == "draining" })
			if view.Status.Drained || !mtuSuspended(a) {
				t.Fatal("error falsely acknowledged native cleanup")
			}
			select {
			case <-operation.done:
				t.Fatal("controller released a blocked native owner")
			default:
			}
			if launch.external.dnsMu.TryLock() {
				launch.external.dnsMu.Unlock()
				t.Fatal("native generation unlocked before actual drain")
			}
			if _, err := a.readDesktopExternalProof(launch); err != nil {
				t.Fatal("measurement cancellation stopped healthy VPN", err)
			}
			if err := os.WriteFile(filepath.Join(launch.directory, "dns-drain-release.fixture"), []byte("release"), 0600); err != nil {
				t.Fatal(err)
			}
			view = desktopDNSWaitForTest(t, a, operation, func(v desktopDNSView) bool { return v.Status.Complete && v.Status.Drained })
			<-operation.done
			if len(view.Status.Results) != 0 || view.ExpiresInMS != 0 || mtuSuspended(a) {
				t.Fatal("cancelled native result remained eligible or retained a drained hold")
			}
		})
	}
}

func TestDesktopDNSRejectsStaleSourceTransportSessionAndExpiredDraft(t *testing.T) {
	for _, change := range []string{"credentials", "selection", "replacement", "network", "expired", "transport", "not-drained", "failed", "selected-row", "pending-start"} {
		t.Run(change, func(t *testing.T) {
			a, _ := desktopDNSControllerFixture(t, "dns-winner")
			operation, request := desktopDNSStartForTest(t, a, "tls")
			desktopDNSWaitForTest(t, a, operation, func(v desktopDNSView) bool { return v.Status.Complete && v.Status.Drained })
			<-operation.done
			request.Transport, request.ResultID = "", "fastest"
			switch change {
			case "credentials":
				a.mu.Lock()
				a.profiles.Profiles[0].External.Hysteria2.Password = "replacement-private-secret"
				a.mu.Unlock()
			case "selection":
				a.mu.Lock()
				a.profiles.SelectedID = "different"
				a.mu.Unlock()
			case "replacement":
				invalidateDesktopDNSResults(a)
			case "network":
				operation.snapshot.launch.external.network = "retired-network-fixture"
			case "expired":
				operation.mu.Lock()
				operation.completedAt = time.Now().Add(-121 * time.Second)
				operation.mu.Unlock()
			case "transport":
				draft, _, err := operation.draft("fastest")
				if err != nil {
					t.Fatal(err)
				}
				draft.Protocol, draft.Port = "udp", 53
				a.mu.Lock()
				a.state = state{Phase: "off", Mode: "off"}
				a.mu.Unlock()
				if w := desktopDNSHTTP(t, a, http.MethodPost, "/api/dns/policy", draft); w.Code != http.StatusConflict {
					t.Fatal("TLS timing became UDP policy", w.Code)
				}
				return
			case "not-drained":
				operation.mu.Lock()
				operation.status.Drained = false
				operation.mu.Unlock()
			case "failed":
				operation.mu.Lock()
				for i := range operation.status.Results {
					operation.status.Results[i].Ready = false
					operation.status.Results[i].Median = nil
				}
				operation.mu.Unlock()
			case "selected-row":
				request.ResultID = "selected"
			case "pending-start":
				a.mu.Lock()
				a.state = state{Phase: "off", Mode: "off"}
				a.cmd = nil
				a.mu.Unlock()
				_, finish, err := a.beginConnectionOperation()
				if err != nil {
					t.Fatal(err)
				}
				finish()
			}
			w := desktopDNSHTTP(t, a, http.MethodPost, "/api/dns/measurement/select", request)
			if w.Code != http.StatusConflict {
				t.Fatal("stale result adopted", change, w.Code, w.Body.String())
			}
		})
	}
}

func TestDesktopDNSRejectsNativeTransportSubstitutionAndMissingCapability(t *testing.T) {
	a, _ := desktopDNSControllerFixture(t, "dns-wrong-transport")
	operation, _ := desktopDNSStartForTest(t, a, "https")
	view := desktopDNSWaitForTest(t, a, operation, func(v desktopDNSView) bool { return v.Status.Complete && v.Status.Drained })
	if view.Status.Stage == "complete" || len(view.Status.Results) != 0 || view.ExpiresInMS != 0 {
		t.Fatal("native public transport substitution was accepted")
	}
	<-operation.done
	for _, protocol := range []string{"wireguard", "amneziawg", "shadowsocks", "hysteria2", "socks5", "http-connect", "https-connect", "openvpn"} {
		if !desktopExternalNativeProtocol(protocol) {
			t.Fatal("ordinary native DNS family missing", protocol)
		}
	}
	plain := externalConnectionTestApp(t, "tor-bridge", false)
	if w := desktopDNSHTTP(t, plain, http.MethodGet, "/api/dns/measurement", nil); w.Code != http.StatusConflict {
		t.Fatal("Tor without real native measurement adapter was fabricated")
	}
}

func TestDesktopDNSDraftCommitSerializesCancellationAndExpiry(t *testing.T) {
	a, _ := desktopDNSControllerFixture(t, "dns-winner")
	operation, _ := desktopDNSStartForTest(t, a, "tcp")
	desktopDNSWaitForTest(t, a, operation, func(v desktopDNSView) bool { return v.Status.Complete && v.Status.Drained })
	<-operation.done
	draft, _, err := operation.draft("fastest")
	if err != nil {
		t.Fatal(err)
	}
	a.mu.Lock()
	a.state = state{Phase: "off", Mode: "off"}
	release, err := operation.beginDraftCommitLocked(a, draft)
	if err != nil {
		a.mu.Unlock()
		t.Fatal(err)
	}
	cancelled := make(chan struct{})
	go func() { operation.invalidate(); close(cancelled) }()
	select {
	case <-cancelled:
		release()
		a.mu.Unlock()
		t.Fatal("cancel crossed the atomic draft commit")
	default:
	}
	release()
	a.mu.Unlock()
	select {
	case <-cancelled:
	case <-time.After(time.Second):
		t.Fatal("draft commit retained cancellation lock")
	}
	if _, _, err := operation.draft("fastest"); err == nil {
		t.Fatal("cancelled receipt survived commit boundary")
	}
}

func TestDesktopDNSNativeRecordRejectsIncompleteDrainAndUnknownIdentity(t *testing.T) {
	a, launch := desktopDNSControllerFixture(t, "dns-winner")
	operation, _ := desktopDNSStartForTest(t, a, "tcp")
	desktopDNSWaitForTest(t, a, operation, func(v desktopDNSView) bool { return v.Status.Complete && v.Status.Drained })
	<-operation.done
	record, err := readDesktopDNSRecord(launch)
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range []string{"session", "source", "config", "nonce", "stage", "drain", "node", "score"} {
		copy := record
		copy.Status = cloneDesktopDNSStatus(record.Status)
		switch change {
		case "session":
			copy.Session = "wrong"
		case "source":
			copy.SourceSHA256 = "wrong"
		case "config":
			copy.ConfigSHA256 = "wrong"
		case "nonce":
			copy.Request = "bad"
		case "stage":
			copy.Status.Stage = "claimed-success"
		case "drain":
			copy.Status.Complete = false
		case "node":
			copy.Status.NodeID = "foreign"
		case "score":
			zero := 0.0
			copy.Status.Results[1].Median = &zero
		}
		raw, _ := json.Marshal(copy)
		decoded, err := decodeDesktopDNSRecord(launch, raw)
		if err == nil {
			err = validateDesktopDNSResults(launch, decoded.Status)
		}
		if err == nil {
			t.Fatal("malformed native receipt accepted", change)
		}
	}
}

func TestDesktopDNSCancelAcknowledgesUnadmittedOldSessionAfterDisconnect(t *testing.T) {
	a, launch := desktopDNSControllerFixture(t, "dns-hold")
	view := desktopDNSCaptureForTest(t, a)
	request := desktopDNSRequest{ProfileID: view.ProfileID, ProfileToken: view.ProfileToken, SessionID: view.SessionID, Request: strings.Repeat("b", 32)}
	if err := prepareDesktopExternalStop(a, launch.command); err != nil {
		t.Fatal(err)
	}
	<-desktopExternalProcessDone(launch)
	a.mu.Lock()
	a.cmd = nil
	a.state = state{Mode: "off", Phase: "off"}
	a.mu.Unlock()
	w := desktopDNSHTTP(t, a, http.MethodPost, "/api/dns/measurement/cancel", request)
	var receipt desktopDNSView
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &receipt) != nil || !receipt.Status.Drained || !receipt.Status.Complete || receipt.SessionID != view.SessionID || receipt.ProfileToken != view.ProfileToken {
		t.Fatal("unadmitted retired request cannot acknowledge no work", w.Code, w.Body.String())
	}
	w = desktopDNSHTTP(t, a, http.MethodGet, "/api/dns/measurement?request_id="+request.Request, nil)
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &receipt) != nil || !receipt.Status.Drained {
		t.Fatal("cancel-before-start tombstone was not retained")
	}
	request.Transport = "https"
	if w = desktopDNSHTTP(t, a, http.MethodPost, "/api/dns/measurement", request); w.Code != http.StatusConflict {
		t.Fatal("old native session reopened work")
	}
}

func desktopDNSPreparedController(t *testing.T, launch *desktopNodeLaunch, profile, entry common.RouterProfile) *app {
	t.Helper()
	root := t.TempDir()
	t.Setenv("HOMEVPN_ROOT", root)
	a, _ := desktopExternalRunCompiledFixture(t, "dns-winner", root, launch)
	a.cfg.ProfilesFile = filepath.Join(root, "profiles.json")
	a.profiles = common.RouterProfileStore{SchemaVersion: common.RouterProfileStoreVersion, SelectedID: profile.ID, Profiles: []common.RouterProfile{profile}}
	if entry.ID != "" {
		a.profiles.Profiles = append(a.profiles.Profiles, entry)
	}
	a.state = state{Connected: true, Phase: "connected", Mode: profile.External.Protocol, RuntimeMode: profile.External.Protocol, RouterID: profile.ID}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	if _, err := a.waitDesktopExternalProof(ctx, launch); err != nil {
		t.Fatal(err)
	}
	a.mu.Lock()
	captureDesktopMTUBaselineLocked(a, launch)
	err := a.persistProfilesLocked()
	a.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	launch.external.mtu.automatic = true
	t.Cleanup(func() { a.mu.Lock(); a.closing = true; a.mu.Unlock(); invalidateDesktopDNSResults(a) })
	return a
}

func TestDesktopDNSAllEightOrdinaryFamiliesUseCapturedNativeMailbox(t *testing.T) {
	for _, protocol := range []string{"wireguard", "amneziawg", "shadowsocks", "hysteria2", "socks5", "http-connect", "https-connect", "openvpn"} {
		t.Run(protocol, func(t *testing.T) {
			var profile common.RouterProfile
			var launch *desktopNodeLaunch
			if protocol == "openvpn" {
				profile, _, launch = desktopOpenVPNCompileFixture(t, desktopOpenVPNCreateFixture(t, common.StartLayerOff))
			} else {
				p, exit := desktopExternalNativeFixture(t, protocol)
				profile = p
				var err error
				launch, err = compileDesktopExternalCaptured(context.Background(), profile, common.RouterProfile{}, exit, true, "", nil, nil, nil)
				if err != nil {
					t.Fatal(err)
				}
			}
			a := desktopDNSPreparedController(t, launch, profile, common.RouterProfile{})
			operation, _ := desktopDNSStartForTest(t, a, "https")
			view := desktopDNSWaitForTest(t, a, operation, func(v desktopDNSView) bool { return v.Status.Complete && v.Status.Drained })
			<-operation.done
			if view.Status.Stage != "complete" || len(view.Status.Results) != 13 {
				t.Fatal("ordinary family lost its actual captured graph mailbox", protocol, view.Status)
			}
		})
	}
}

func TestDesktopDNSHomeEntryPolicyAndCredentialsRemainCaptured(t *testing.T) {
	entry, files := desktopNodeFixture(t, "198.51.100.44")
	entry.SocksHost, entry.SocksPort, entry.SocksUsername, entry.SocksPassword = "10.77.0.1", 1080, "captured-entry", "captured-secret"
	profile, exit := desktopExternalNativeFixture(t, "hysteria2")
	profile.External.ResponseProbe = &common.ExternalResponseProbe{URL: "https://" + exit.Server + "/node-response", ServerName: "exit.example.test"}
	exit, err := standardExitFromExternalProfile(profile)
	if err != nil {
		t.Fatal(err)
	}
	profile.MultihopEnabled, profile.MultihopEntryID, profile.MultihopExitID = true, entry.ID, profile.ID
	profile.MultihopEntryMode, profile.MultihopExecution = "wg", "auto"
	profile.DNSMode, profile.DNSProtocol, profile.DNSHost, profile.DNSPort, profile.DNSServerName, profile.DNSPath = "home", "https", entry.AdGuardIPv4, 8443, "home.example.test", "/private-dns"
	launch, err := compileDesktopExternalCaptured(context.Background(), profile, entry, exit, false, "", files, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	a := desktopDNSPreparedController(t, launch, profile, entry)
	operation, request := desktopDNSStartForTest(t, a, "tls")
	view := desktopDNSWaitForTest(t, a, operation, func(v desktopDNSView) bool { return v.Status.Complete && v.Status.Drained })
	<-operation.done
	if view.Status.Stage != "complete" || len(view.Status.Results) != 13 {
		t.Fatal("Home entry native result", view.Status)
	}
	selected := view.Status.Results[0]
	if selected.Kind != "selected" || selected.Address != entry.AdGuardIPv4 || selected.Port != 8443 || selected.Transport != "https" || selected.ServerName != "home.example.test" || selected.Path != "/private-dns" || selected.Route == "custom-exit" {
		t.Fatal("selected Home policy was substituted or mislabeled", selected)
	}
	if launch.external.execution != "local" {
		t.Fatal("DNS measurement reran Compare selection")
	}
	request.Transport, request.ResultID = "", "fastest"
	a.mu.Lock()
	a.profiles.Profiles[1].APIToken = "replacement-entry-private-token"
	a.mu.Unlock()
	if w := desktopDNSHTTP(t, a, http.MethodPost, "/api/dns/measurement/select", request); w.Code != http.StatusConflict {
		t.Fatal("entry credentials changed without retiring DNS result", w.Code)
	}
}

func TestDesktopDNSCleanupUsesPinnedDirectoryAndPreservesReplacement(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	owner := &desktopExternalRuntime{session: strings.Repeat("a", 32), expected: mobilemultihop.ExternalProofResult{ExitID: "owned-exit", SourceSHA256: strings.Repeat("b", 64), ConfigSHA256: strings.Repeat("c", 64)}}
	launch := &desktopNodeLaunch{external: owner}
	if err := captureDesktopRuntimeDirectory(launch, directory); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = launch.directoryRoot.Close() })
	request := desktopDNSNativeRequest{Schema: 1, Session: owner.session, SourceSHA256: owner.expected.SourceSHA256, ConfigSHA256: owner.expected.ConfigSHA256, Generation: 1, Request: strings.Repeat("d", 32), Transport: "https"}
	retired := directory + "-retired"
	renamed := true
	if err := os.Rename(directory, retired); err != nil {
		if runtime.GOOS != "windows" || !errors.Is(err, syscall.Errno(5)) && !errors.Is(err, syscall.Errno(32)) {
			t.Fatal(err)
		}
		renamed, retired = false, directory
	}
	foreign := []byte(`{"replacement":"untouched"}`)
	if renamed {
		if err := os.Mkdir(directory, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(directory, "dns-cancel.json"), foreign, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := writeDesktopDNSCleanupCancel(launch, request); err != nil {
		t.Fatal(err)
	}
	if err := writeDesktopDNSCleanupCancel(launch, request); err != nil {
		t.Fatal("identical cleanup retry", err)
	}
	raw, err := os.ReadFile(filepath.Join(retired, "dns-cancel.json"))
	var actual desktopDNSNativeRequest
	if err != nil || json.Unmarshal(raw, &actual) != nil || actual != request {
		t.Fatal("cleanup did not follow the exact old directory", err)
	}
	wrong := request
	wrong.Request = strings.Repeat("e", 32)
	if err := writeDesktopDNSCleanupCancel(launch, wrong); err == nil {
		t.Fatal("another DNS request replaced captured cleanup input")
	}
	status := desktopDNSNativeRecord{desktopDNSNativeRequest: request, Status: dnsmeasure.Status{Schema: 1, NodeID: "owned-exit", SessionID: request.Session, Request: request.Request, PublicTransport: request.Transport, Stage: "cancelled", Complete: true, Drained: true, Failure: "fixture native drain", Results: []dnsmeasure.Result{}}}
	raw, _ = json.Marshal(status)
	if err := os.WriteFile(filepath.Join(retired, "dns-status.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	if record, err := readDesktopDNSDrainRecord(launch); err != nil || record.desktopDNSNativeRequest != request || !record.Status.Drained {
		t.Fatal("captured directory drain receipt lost", err)
	}
	if renamed {
		if _, err := readDesktopDNSRecord(launch); err == nil {
			t.Fatal("retired cleanup receipt was used as current measurement evidence")
		}
		actual, err := os.ReadFile(filepath.Join(directory, "dns-cancel.json"))
		if err != nil || !bytes.Equal(actual, foreign) {
			t.Fatal("cleanup touched replacement directory")
		}
	}
}
