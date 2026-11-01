package main

import (
	"bytes"
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"router-vpn/internal/hopmeasure"
	"router-vpn/internal/mobilemultihop"
	"router-vpn/internal/mobiletor"
)

// This actual child process exercises only the native mailbox/controller
// protocol. Its explicit synthetic statistics are not network evidence; the
// generated Box fixture separately exchanges all 50 real TLS responses.
func desktopLatencyChildFixture(kind, directory string, expected mobilemultihop.ExternalProofResult, write func(string, any)) func() {
	if !strings.HasPrefix(kind, "latency-") {
		return func() {}
	}
	record := desktopLatencyNativeRecord{desktopLatencyNativeRequest: desktopLatencyNativeRequest{Schema: 1, Session: expected.SessionID, SourceSHA256: expected.SourceSHA256, ConfigSHA256: expected.ConfigSHA256, NodeID: expected.ExitID}, Status: hopmeasure.Status{Stage: "idle", Complete: true, Drained: true, Results: []hopmeasure.Result{}}}
	write("latency-status.json", record)
	read := func(name string, target any) bool {
		raw, err := os.ReadFile(filepath.Join(directory, name))
		return err == nil && decodeRelayControlJSON(raw, target) == nil
	}
	remove := func() {
		for _, name := range []string{"latency-request.json", "latency-cancel.json"} {
			var captured desktopLatencyNativeRequest
			if read(name, &captured) && captured == record.desktopLatencyNativeRequest {
				_ = os.Remove(filepath.Join(directory, name))
			}
		}
	}
	return func() {
		var request desktopLatencyNativeRequest
		valid := func(name string) bool {
			return read(name, &request) && request.Schema == 1 && request.Session == expected.SessionID && request.SourceSHA256 == expected.SourceSHA256 && request.ConfigSHA256 == expected.ConfigSHA256 && request.NodeID == expected.ExitID && request.Generation == record.Generation+1
		}
		if record.Status.Complete && record.Status.Drained && (valid("latency-request.json") || valid("latency-cancel.json")) {
			record = desktopLatencyNativeRecord{desktopLatencyNativeRequest: request, Status: hopmeasure.Status{Request: request.Request, Stage: "exit: HTTPS response 1/50", Results: []hopmeasure.Result{}}}
		}
		if record.Generation == 0 {
			return
		}
		var cancel desktopLatencyNativeRequest
		if read("latency-cancel.json", &cancel) && cancel == record.desktopLatencyNativeRequest {
			record.Status = hopmeasure.Status{Request: record.Request, Stage: "cancelled", Complete: true, Failure: "explicit IPC cancellation fixture", Results: []hopmeasure.Result{}}
			_, release := os.Stat(filepath.Join(directory, "latency-drain-release.fixture"))
			record.Status.Drained = kind != "latency-cancel-delay" && kind != "latency-read-fail" || release == nil
			if record.Status.Drained {
				remove()
			}
		} else if !record.Status.Complete && kind != "latency-hold" && kind != "latency-cancel-delay" && kind != "latency-read-fail" {
			record.Status = desktopLatencyStatusFixture(record.Request, expected.ExitID)
			if kind == "latency-incomplete" {
				record.Status.Results[0].Benchmark.Distribution.Samples = 49
			}
			if kind == "latency-undrained" {
				record.Status.Drained = false
			}
			if record.Status.Drained {
				remove()
			}
		}
		published := record
		if kind == "latency-read-fail" && !record.Status.Drained {
			published.SourceSHA256 = strings.Repeat("f", 64)
		}
		write("latency-status.json", published)
	}
}

func desktopTorLatencyChildFixture(kind, directory string, expected mobiletor.DesktopBridgeMetadata, write func(string, any)) func() {
	// This converts only explicit IPC fixture metadata. Production Tor and
	// ordinary graphs retain separate native proof/runtime implementations.
	return desktopLatencyChildFixture(strings.TrimPrefix(kind, "tor-"), directory, mobilemultihop.ExternalProofResult{
		SessionID: expected.SessionID, SourceSHA256: expected.SourceSHA256, ConfigSHA256: expected.ConfigSHA256, ExitID: expected.NodeID,
	}, write)
}

func TestDesktopExternalLatencyTorUsesOwnNativeSessionAndDrain(t *testing.T) {
	for _, kind := range []string{"tor-latency-winner", "tor-latency-cancel-delay"} {
		t.Run(kind, func(t *testing.T) {
			a, launch := desktopTorDNSControllerFixture(t, kind)
			t.Cleanup(func() {
				invalidateDesktopLatencyResults(a)
				_ = os.WriteFile(filepath.Join(launch.directory, "latency-drain-release.fixture"), []byte("release"), 0600)
				slot := a.desktopLatencyFor()
				slot.mu.Lock()
				operation := slot.current
				slot.mu.Unlock()
				if operation != nil {
					select {
					case <-operation.done:
					case <-time.After(4 * time.Second):
						t.Error("Tor latency fixture did not drain")
					}
				}
			})
			before := cloneRouterProfileStore(a.profiles)
			operation, request := desktopLatencyStartTest(t, a)
			if kind == "tor-latency-cancel-delay" {
				desktopLatencyWaitTest(t, a, operation, func(v desktopLatencyView) bool { return desktopLatencyNativePhase(v.Status.Stage) })
				if w := desktopLatencyHTTP(t, a, http.MethodPost, "/api/speed-lab/external-latency/cancel", request); w.Code != http.StatusAccepted {
					t.Fatal(w.Code, w.Body.String())
				}
				desktopLatencyWaitTest(t, a, operation, func(v desktopLatencyView) bool { return v.Status.Stage == "draining" })
				if !mtuSuspended(a) {
					t.Fatal("Tor latency released MTU before native drain")
				}
				if err := os.WriteFile(filepath.Join(launch.directory, "latency-drain-release.fixture"), []byte("release"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			view := desktopLatencyWaitTest(t, a, operation, func(v desktopLatencyView) bool { return v.Status.Complete && v.Status.Drained })
			<-operation.done
			if view.SessionID != launch.tor.expected.SessionID || view.SourceSHA256 != launch.tor.expected.SourceSHA256 || view.ConfigSHA256 != launch.tor.expected.ConfigSHA256 || launch.external != nil || !reflect.DeepEqual(before, a.profiles) || a.cmd != launch.command {
				t.Fatal("Tor adopted ordinary/foreign metadata or mutated saved path", view)
			}
			if kind == "tor-latency-winner" && (view.Status.Stage != "complete" || len(view.Status.Results) != 1 || view.Status.Results[0].ID != launch.tor.expected.NodeID) {
				t.Fatal("Tor result lost exact actual node ID", view)
			}
			if kind != "tor-latency-winner" && len(view.Status.Results) != 0 {
				t.Fatal("cancelled Tor retained score")
			}
		})
	}
}

func desktopLatencyStatusFixture(request, node string) hopmeasure.Status {
	return hopmeasure.Status{Request: request, Stage: "complete", Complete: true, Drained: true, Results: []hopmeasure.Result{{ID: node, Role: "exit", Kind: "public-path", Label: "External exit → Cloudflare edge", Ready: true, Benchmark: &hopmeasure.LatencyBenchmark{Schema: 1, Measurement: "routed-https-response-after-tls", Endpoint: "https://speed.cloudflare.com/__down?bytes=1", Attempts: 50, Distribution: &hopmeasure.Latency{Samples: 50, Min: 1, Median: 4, Average: 5, P90: 8, Max: 10, Jitter: 2}, TrimmedMean: 4.5}}}}
}

func desktopLatencyControllerFixture(t *testing.T, kind string) (*app, *desktopNodeLaunch) {
	t.Helper()
	a, launch := desktopDNSControllerFixture(t, kind)
	t.Cleanup(func() {
		invalidateDesktopLatencyResults(a)
		_ = os.WriteFile(filepath.Join(launch.directory, "latency-drain-release.fixture"), []byte("release"), 0600)
		slot := a.desktopLatencyFor()
		slot.mu.Lock()
		operation := slot.current
		slot.mu.Unlock()
		if operation != nil {
			select {
			case <-operation.done:
			case <-time.After(4 * time.Second):
				t.Error("latency controller fixture failed to drain")
			}
		}
	})
	return a, launch
}

func desktopLatencyHTTP(t *testing.T, a *app, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var raw []byte
	if body != nil {
		var err error
		raw, err = json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
	}
	mux := http.NewServeMux()
	registerSpeedLabRoutes(mux, a)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest(method, path, bytes.NewReader(raw)))
	return w
}

func desktopLatencyCaptureTest(t *testing.T, a *app) desktopLatencyView {
	t.Helper()
	w := desktopLatencyHTTP(t, a, http.MethodGet, "/api/speed-lab/external-latency", nil)
	var view desktopLatencyView
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &view) != nil || view.Status.Stage != "idle" || !view.Status.Drained || view.SourceSHA256 == "" || view.ConfigSHA256 == "" || view.ProfileToken == "" {
		t.Fatal("latency capture", w.Code, w.Body.String())
	}
	return view
}

func desktopLatencyStartTest(t *testing.T, a *app) (*desktopLatencyOperation, desktopLatencyRequest) {
	t.Helper()
	view := desktopLatencyCaptureTest(t, a)
	id, err := randomHex(16)
	if err != nil {
		t.Fatal(err)
	}
	request := desktopLatencyRequest{ProfileID: view.ProfileID, ProfileToken: view.ProfileToken, SessionID: view.SessionID, Request: id}
	w := desktopLatencyHTTP(t, a, http.MethodPost, "/api/speed-lab/external-latency", request)
	if w.Code != http.StatusAccepted {
		t.Fatal("latency start", w.Code, w.Body.String())
	}
	slot := a.desktopLatencyFor()
	slot.mu.Lock()
	operation := slot.current
	slot.mu.Unlock()
	if operation == nil || operation.request != id {
		t.Fatal("no exact accepted owner")
	}
	return operation, request
}

func desktopLatencyWaitTest(t *testing.T, a *app, o *desktopLatencyOperation, accept func(desktopLatencyView) bool) desktopLatencyView {
	t.Helper()
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		view := o.view(a)
		if accept(view) {
			return view
		}
		select {
		case <-deadline.C:
			t.Fatal("latency boundary not reached", view)
		case <-tick.C:
		}
	}
}

func TestDesktopExternalLatencySelectedPathPreservesProfilesAndExactIdentity(t *testing.T) {
	a, launch := desktopLatencyControllerFixture(t, "latency-winner")
	before := cloneRouterProfileStore(a.profiles)
	operation, request := desktopLatencyStartTest(t, a)
	view := desktopLatencyWaitTest(t, a, operation, func(v desktopLatencyView) bool { return v.Status.Complete && v.Status.Drained })
	<-operation.done
	if view.Status.Stage != "complete" || view.MeasuredAt <= 0 || view.SessionID != launch.external.session || len(view.Status.Results) != 1 || view.Status.Results[0].Benchmark.TrimmedMean != 4.5 || mtuSuspended(a) {
		t.Fatal("unowned or incomplete native receipt", view)
	}
	if !reflect.DeepEqual(before, a.profiles) || a.cmd != launch.command || launch.external.execution != "local" {
		t.Fatal("latency changed source, selection, credentials, usage, MTU or proved execution")
	}
	if w := desktopLatencyHTTP(t, a, http.MethodPost, "/api/speed-lab/external-latency", request); w.Code != http.StatusConflict {
		t.Fatal("request replay admitted")
	}
	view.Status.Results[0].Benchmark.TrimmedMean = 1000
	if operation.view(a).Status.Results[0].Benchmark.TrimmedMean != 4.5 {
		t.Fatal("view escaped mutable native record")
	}
	a.mu.Lock()
	a.profiles.Profiles[0].DNSHost = "9.9.9.9"
	a.mu.Unlock()
	if current := operation.view(a); len(current.Status.Results) != 0 || current.MeasuredAt != 0 {
		t.Fatal("changed source retained current-path score")
	}
}

func TestDesktopExternalLatencyCancellationRetainsMTUAndGenerationUntilDrain(t *testing.T) {
	for _, kind := range []string{"latency-cancel-delay", "latency-read-fail"} {
		t.Run(kind, func(t *testing.T) {
			a, launch := desktopLatencyControllerFixture(t, kind)
			operation, request := desktopLatencyStartTest(t, a)
			if kind == "latency-cancel-delay" {
				desktopLatencyWaitTest(t, a, operation, func(v desktopLatencyView) bool { return desktopLatencyNativePhase(v.Status.Stage) })
				wrong := request
				wrong.SessionID = strings.Repeat("f", 32)
				if w := desktopLatencyHTTP(t, a, http.MethodPost, "/api/speed-lab/external-latency/cancel", wrong); w.Code != http.StatusConflict {
					t.Fatal("foreign cancellation accepted")
				}
				if w := desktopLatencyHTTP(t, a, http.MethodPost, "/api/speed-lab/external-latency/cancel", request); w.Code != http.StatusAccepted {
					t.Fatal("cancel", w.Code, w.Body.String())
				}
			}
			view := desktopLatencyWaitTest(t, a, operation, func(v desktopLatencyView) bool { return v.Status.Stage == "draining" })
			if view.Status.Drained || !mtuSuspended(a) {
				t.Fatal("pending native worker released MTU")
			}
			if launch.external.latencyMu.TryLock() {
				launch.external.latencyMu.Unlock()
				t.Fatal("pending native generation unlocked")
			}
			if finish, err := beginSpeedLabRun(a); err == nil {
				finish()
				t.Fatal("pending native50 released shared Speed Lab owner")
			}
			if _, err := a.readDesktopExternalProof(launch); err != nil {
				t.Fatal("latency cancellation stopped proved tunnel", err)
			}
			if err := os.WriteFile(filepath.Join(launch.directory, "latency-drain-release.fixture"), []byte("release"), 0600); err != nil {
				t.Fatal(err)
			}
			view = desktopLatencyWaitTest(t, a, operation, func(v desktopLatencyView) bool { return v.Status.Complete && v.Status.Drained })
			<-operation.done
			if len(view.Status.Results) != 0 || view.MeasuredAt != 0 || mtuSuspended(a) {
				t.Fatal("cancelled partial result acquired score or retained drained lease")
			}
		})
	}
}

func TestDesktopExternalLatencyRejectsSourceSelectionAndReplacementOwners(t *testing.T) {
	for _, change := range []string{"dns", "credential", "selection", "protection", "replacement", "temporary"} {
		t.Run(change, func(t *testing.T) {
			a, launch := desktopLatencyControllerFixture(t, "latency-hold")
			operation, _ := desktopLatencyStartTest(t, a)
			desktopLatencyWaitTest(t, a, operation, func(v desktopLatencyView) bool { return desktopLatencyNativePhase(v.Status.Stage) })
			a.mu.Lock()
			switch change {
			case "dns":
				a.profiles.Profiles[0].DNSHost = "1.0.0.1"
			case "credential":
				a.profiles.Profiles[0].External.Hysteria2.Password = "replacement-secret"
			case "selection":
				a.profiles.SelectedID = "other"
			case "protection":
				a.profiles.Profiles[0].KillSwitchPolicy = "always"
			case "replacement":
				desktopNodeOwners.Store(a, &desktopNodeLaunch{command: launch.command})
			case "temporary":
				speedLabTemporaryOwners.Store(a, &speedLabTemporaryOwner{})
			}
			a.mu.Unlock()
			if change == "temporary" {
				defer speedLabTemporaryOwners.Delete(a)
			}
			view := desktopLatencyWaitTest(t, a, operation, func(v desktopLatencyView) bool { return v.Status.Complete && v.Status.Drained })
			<-operation.done
			if len(view.Status.Results) != 0 || view.MeasuredAt != 0 || a.cmd != launch.command || desktopExternalProcessExited(launch) {
				t.Fatal("stale measurement published or stopped another selected runtime", view)
			}
		})
	}
}

func TestDesktopExternalLatencyStrict50RejectsIncompleteOrForgedResults(t *testing.T) {
	launch := &desktopNodeLaunch{external: &desktopExternalRuntime{session: strings.Repeat("a", 32), expected: mobilemultihop.ExternalProofResult{ExitID: "node", SourceSHA256: strings.Repeat("b", 64), ConfigSHA256: strings.Repeat("c", 64)}}}
	valid := desktopLatencyStatusFixture(strings.Repeat("d", 32), "node")
	if err := validateDesktopLatencyResults(launch, valid); err != nil {
		t.Fatal(err)
	}
	changes := map[string]func(*hopmeasure.Status){"undrained": func(s *hopmeasure.Status) { s.Drained = false }, "49": func(s *hopmeasure.Status) { s.Results[0].Benchmark.Distribution.Samples = 49 }, "attempts": func(s *hopmeasure.Status) { s.Results[0].Benchmark.Attempts = 51 }, "failed": func(s *hopmeasure.Status) { s.Results[0].Benchmark.Failed = 1 }, "zero": func(s *hopmeasure.Status) { s.Results[0].Benchmark.TrimmedMean = 0 }, "nan": func(s *hopmeasure.Status) { s.Results[0].Benchmark.TrimmedMean = math.NaN() }, "endpoint": func(s *hopmeasure.Status) { s.Results[0].Benchmark.Endpoint = "https://other.invalid/" }, "metric": func(s *hopmeasure.Status) { s.Results[0].Benchmark.Measurement = "tcp-handshake" }, "node": func(s *hopmeasure.Status) { s.Results[0].ID = "replacement" }, "partial": func(s *hopmeasure.Status) { s.Results[0].Ready = false }, "throughput": func(s *hopmeasure.Status) { s.Results[0].Download = &hopmeasure.Transfer{} }, "role": func(s *hopmeasure.Status) { s.Results[0].Role = "entry" }, "duplicate": func(s *hopmeasure.Status) { s.Results = append(s.Results, s.Results[0]) }, "bounds": func(s *hopmeasure.Status) { s.Results[0].Benchmark.Distribution.P90 = 0.5 }}
	for name, edit := range changes {
		t.Run(name, func(t *testing.T) {
			status := cloneDesktopLatencyStatus(valid)
			edit(&status)
			if validateDesktopLatencyResults(launch, status) == nil {
				t.Fatal("invalid native result accepted")
			}
		})
	}
	for _, kind := range []string{"latency-incomplete", "latency-undrained"} {
		t.Run(kind, func(t *testing.T) {
			a, _ := desktopLatencyControllerFixture(t, kind)
			operation, request := desktopLatencyStartTest(t, a)
			if kind == "latency-undrained" {
				pending := desktopLatencyWaitTest(t, a, operation, func(v desktopLatencyView) bool { return v.Status.Stage == "verifying" })
				if len(pending.Status.Results) != 0 {
					t.Fatal("undrained native score escaped the private result boundary")
				}
				if w := desktopLatencyHTTP(t, a, http.MethodPost, "/api/speed-lab/external-latency/cancel", request); w.Code != http.StatusAccepted {
					t.Fatal(w.Code)
				}
			}
			view := desktopLatencyWaitTest(t, a, operation, func(v desktopLatencyView) bool { return v.Status.Complete && v.Status.Drained })
			<-operation.done
			if len(view.Status.Results) != 0 || view.MeasuredAt != 0 {
				t.Fatal("unproved partial result was published")
			}
		})
	}
}

func TestDesktopExternalLatencyQueuedCancelAndTemporaryCapture(t *testing.T) {
	a, _ := desktopLatencyControllerFixture(t, "latency-winner")
	view := desktopLatencyCaptureTest(t, a)
	request := desktopLatencyRequest{ProfileID: view.ProfileID, ProfileToken: view.ProfileToken, SessionID: view.SessionID, Request: strings.Repeat("d", 32)}
	if w := desktopLatencyHTTP(t, a, http.MethodPost, "/api/speed-lab/external-latency/cancel", request); w.Code != http.StatusOK {
		t.Fatal(w.Code, w.Body.String())
	}
	if w := desktopLatencyHTTP(t, a, http.MethodPost, "/api/speed-lab/external-latency", request); w.Code != http.StatusConflict {
		t.Fatal("cancelled queued start opened native work")
	}
	speedLabTemporaryOwners.Store(a, &speedLabTemporaryOwner{})
	defer speedLabTemporaryOwners.Delete(a)
	if w := desktopLatencyHTTP(t, a, http.MethodGet, "/api/speed-lab/external-latency", nil); w.Code != http.StatusConflict {
		t.Fatal("selected public API borrowed a temporary connection")
	}
}

func TestDesktopExternalLatencyUncertainWriteCancelsOnlyCapturedGeneration(t *testing.T) {
	a, launch := desktopLatencyControllerFixture(t, "latency-winner")
	foreign := []byte(`{"foreign_request":"preserve"}`)
	if err := os.WriteFile(filepath.Join(launch.directory, "latency-request.json"), foreign, 0600); err != nil {
		t.Fatal(err)
	}
	operation, _ := desktopLatencyStartTest(t, a)
	view := desktopLatencyWaitTest(t, a, operation, func(v desktopLatencyView) bool { return v.Status.Complete && v.Status.Drained })
	<-operation.done
	if len(view.Status.Results) != 0 || view.MeasuredAt != 0 || mtuSuspended(a) || !launch.external.latencyFailed {
		t.Fatal("uncertain publication adopted or abandoned its generation", view)
	}
	actual, err := os.ReadFile(filepath.Join(launch.directory, "latency-request.json"))
	if err != nil || !bytes.Equal(actual, foreign) {
		t.Fatal("cleanup deleted foreign native request", err)
	}
	if _, err := a.readDesktopExternalProof(launch); err != nil {
		t.Fatal("uncertain measurement write stopped proved VPN", err)
	}
}

func TestDesktopExternalLatencyNativeCloseWhileDraining(t *testing.T) {
	a, launch := desktopLatencyControllerFixture(t, "latency-cancel-delay")
	operation, request := desktopLatencyStartTest(t, a)
	desktopLatencyWaitTest(t, a, operation, func(v desktopLatencyView) bool { return desktopLatencyNativePhase(v.Status.Stage) })
	if w := desktopLatencyHTTP(t, a, http.MethodPost, "/api/speed-lab/external-latency/cancel", request); w.Code != http.StatusAccepted {
		t.Fatal(w.Code)
	}
	desktopLatencyWaitTest(t, a, operation, func(v desktopLatencyView) bool { return v.Status.Stage == "draining" })
	if !mtuSuspended(a) {
		t.Fatal("native activity was not retained")
	}
	if err := prepareDesktopExternalStop(a, launch.command); err != nil {
		t.Fatal(err)
	}
	select {
	case <-desktopExternalProcessDone(launch):
	case <-time.After(4 * time.Second):
		t.Fatal("original native IPC process failed to close")
	}
	view := desktopLatencyWaitTest(t, a, operation, func(v desktopLatencyView) bool { return v.Status.Complete && v.Status.Drained })
	<-operation.done
	if len(view.Status.Results) != 0 || mtuSuspended(a) || !launch.external.latencyFailed {
		t.Fatal("closed native owner retained a measurement or lease", view)
	}
}

func TestDesktopExternalLatencyInvalidationCannotBeUndoneBySourceReturn(t *testing.T) {
	a, _ := desktopLatencyControllerFixture(t, "latency-hold")
	operation, _ := desktopLatencyStartTest(t, a)
	desktopLatencyWaitTest(t, a, operation, func(v desktopLatencyView) bool { return desktopLatencyNativePhase(v.Status.Stage) })
	a.mu.Lock()
	original := a.profiles.Profiles[0].DNSHost
	a.profiles.Profiles[0].DNSHost = "replacement.invalid"
	a.mu.Unlock()
	// This is the shipping connection/shutdown/native-monitor invalidation
	// hook. Restoring identical bytes cannot restore its old decision owner.
	invalidateDesktopDNSResults(a)
	a.mu.Lock()
	a.profiles.Profiles[0].DNSHost = original
	a.mu.Unlock()
	view := desktopLatencyWaitTest(t, a, operation, func(v desktopLatencyView) bool { return v.Status.Complete && v.Status.Drained })
	<-operation.done
	if len(view.Status.Results) != 0 || view.MeasuredAt != 0 || !operation.invalid {
		t.Fatal("same source bytes revived cancelled decision")
	}
}

func TestDesktopExternalLatencyForeignCancelCannotRetireNewOperation(t *testing.T) {
	a, launch := desktopLatencyControllerFixture(t, "latency-cancel-delay")
	old, oldRequest := desktopLatencyStartTest(t, a)
	desktopLatencyWaitTest(t, a, old, func(v desktopLatencyView) bool { return desktopLatencyNativePhase(v.Status.Stage) })
	if w := desktopLatencyHTTP(t, a, http.MethodPost, "/api/speed-lab/external-latency/cancel", oldRequest); w.Code != http.StatusAccepted {
		t.Fatal(w.Code)
	}
	if err := os.WriteFile(filepath.Join(launch.directory, "latency-drain-release.fixture"), []byte("release"), 0600); err != nil {
		t.Fatal(err)
	}
	desktopLatencyWaitTest(t, a, old, func(v desktopLatencyView) bool { return v.Status.Complete && v.Status.Drained })
	<-old.done
	if err := os.Remove(filepath.Join(launch.directory, "latency-drain-release.fixture")); err != nil {
		t.Fatal(err)
	}
	current, request := desktopLatencyStartTest(t, a)
	desktopLatencyWaitTest(t, a, current, func(v desktopLatencyView) bool { return desktopLatencyNativePhase(v.Status.Stage) })
	if w := desktopLatencyHTTP(t, a, http.MethodPost, "/api/speed-lab/external-latency/cancel", oldRequest); w.Code != http.StatusOK {
		t.Fatal("late old cancellation", w.Code)
	}
	foreign := request
	foreign.SessionID = strings.Repeat("f", 32)
	if w := desktopLatencyHTTP(t, a, http.MethodPost, "/api/speed-lab/external-latency/cancel", foreign); w.Code != http.StatusConflict {
		t.Fatal("foreign session cancellation accepted")
	}
	current.mu.Lock()
	invalid := current.invalid
	current.mu.Unlock()
	if invalid || a.cmd != launch.command || !mtuSuspended(a) {
		t.Fatal("foreign cancellation touched newer operation")
	}
}

func TestDesktopExternalLatencyTombstonesAreBoundToProvedNativeSession(t *testing.T) {
	a, _ := desktopLatencyControllerFixture(t, "latency-winner")
	view := desktopLatencyCaptureTest(t, a)
	slot := a.desktopLatencyFor()
	slot.mu.Lock()
	slot.session = strings.Repeat("f", 32)
	for index := 0; index < 256; index++ {
		slot.cancelled[string(rune(index))] = desktopLatencyView{SessionID: slot.session}
	}
	slot.mu.Unlock()
	request := desktopLatencyRequest{ProfileID: view.ProfileID, ProfileToken: view.ProfileToken, SessionID: view.SessionID, Request: strings.Repeat("e", 32)}
	if w := desktopLatencyHTTP(t, a, http.MethodPost, "/api/speed-lab/external-latency/cancel", request); w.Code != http.StatusOK {
		t.Fatal("new actual session inherited old cancellation exhaustion", w.Code, w.Body.String())
	}
	foreign := request
	foreign.SessionID = strings.Repeat("f", 32)
	foreign.Request = strings.Repeat("d", 32)
	if w := desktopLatencyHTTP(t, a, http.MethodPost, "/api/speed-lab/external-latency/cancel", foreign); w.Code != http.StatusConflict {
		t.Fatal("foreign cancellation rotated current registry")
	}
	foreign = request
	foreign.ProfileToken = "foreign-source"
	foreign.Request = strings.Repeat("d", 32)
	if w := desktopLatencyHTTP(t, a, http.MethodPost, "/api/speed-lab/external-latency/cancel", foreign); w.Code != http.StatusConflict {
		t.Fatal("foreign source tombstoned an unstarted request")
	}
	slot.mu.Lock()
	session, count := slot.session, len(slot.cancelled)
	slot.mu.Unlock()
	if session != view.SessionID || count != 1 {
		t.Fatal("queued cancellation lost exact session bound", session, count)
	}
	if w := desktopLatencyHTTP(t, a, http.MethodPost, "/api/speed-lab/external-latency", request); w.Code != http.StatusConflict {
		t.Fatal("queued current-session tombstone was discarded")
	}
}
