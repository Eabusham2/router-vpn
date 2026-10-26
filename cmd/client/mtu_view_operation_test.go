package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"router-vpn/internal/mobilemtu"
)

func TestMTUViewRequestRejectsAmbiguousAndForeignInputs(t *testing.T) {
	for _, raw := range []string{`null`, `[]`, `{} {}`, `{"unknown":true}`, `{"request_id":null}`, `{"session_id":null}`, `{"profile_id":null}`, `{"request_id":"abc"}`, `{"request_id":"` + strings.Repeat("a", 32) + `","request_id":"` + strings.Repeat("b", 32) + `"}`, strings.Repeat(" ", 1025) + `{}`} {
		if _, err := readMTUViewRequest(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/api/mtu/retest", strings.NewReader(raw))); err == nil {
			t.Fatal("ambiguous or unbounded MTU request accepted", raw[:min(len(raw), 80)])
		}
	}
	for _, raw := range []string{`{}`, `{"request_id":"` + strings.Repeat("a", 32) + `","session_id":"captured","profile_id":"router"}`} {
		if _, err := readMTUViewRequest(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/api/mtu/retest", strings.NewReader(raw))); err != nil {
			t.Fatal("compatible owned MTU request rejected", err)
		}
	}
}

func TestMTUViewLegacyStatusCancelAndDrainKeepTheirOwner(t *testing.T) {
	a, snapshot := newMTUTransactionFixture(t)
	t.Cleanup(func() { mtuViewSlots.Delete(a) })
	identity := mtuViewIdentity{Session: snapshot.SessionID, Profile: snapshot.Profile.ID}
	request := mtuViewRequest{Request: strings.Repeat("a", 32), Session: identity.Session, Profile: identity.Profile}
	ctx, operation, err := beginMTUViewOperation(a, context.Background(), request, identity)
	if err != nil {
		t.Fatal(err)
	}
	writer := &mtuViewResponse{ResponseWriter: httptest.NewRecorder(), operation: operation}
	updateMTUViewPhase(ctx, "measuring", 1420)
	read := func(path string) (*httptest.ResponseRecorder, mobilemtu.Status) {
		t.Helper()
		response := httptest.NewRecorder()
		a.desktopMTUStatus(response, httptest.NewRequest(http.MethodGet, path, nil))
		var decoded struct {
			Session string           `json:"session_id"`
			Profile string           `json:"profile_id"`
			Status  mobilemtu.Status `json:"status"`
			Allowed *bool            `json:"optimization_allowed"`
		}
		if response.Code == http.StatusOK {
			if json.Unmarshal(response.Body.Bytes(), &decoded) != nil || decoded.Session != identity.Session || decoded.Profile != identity.Profile || decoded.Allowed == nil || !*decoded.Allowed {
				t.Fatal("status changed its connection identity")
			}
		}
		return response, decoded.Status
	}
	url := "/api/mtu/status?request_id=" + request.Request + "&session_id=" + identity.Session
	if response, status := read(url); response.Code != http.StatusOK || !status.Running || status.Complete || status.Measured || status.Phase != "measuring" || status.Request != request.Request || len(status.Candidates) != 0 {
		t.Fatal("legacy progress fabricated measurement or lost owner", response.Code, status)
	}
	if response, _ := read("/api/mtu/status?request_id=" + strings.Repeat("b", 32) + "&session_id=" + identity.Session); response.Code != http.StatusNotFound {
		t.Fatal("unknown poll adopted the active measurement", response.Code)
	}
	for _, session := range []string{"replacement", identity.Session} {
		response := httptest.NewRecorder()
		a.cancelDesktopMTURoute(response, httptest.NewRequest(http.MethodPost, "/api/mtu/cancel", strings.NewReader(`{"request_id":"`+request.Request+`","session_id":"`+session+`"}`)))
		if session != identity.Session {
			if response.Code != http.StatusConflict || ctx.Err() != nil {
				t.Fatal("wrong session canceled the captured operation")
			}
		} else if response.Code != http.StatusOK || ctx.Err() != context.Canceled {
			t.Fatal("captured cancellation did not reach its context")
		}
	}
	if _, status := read(url); !status.Running || status.Complete || status.Phase != "canceling" || status.Restored {
		t.Fatal("cancel acknowledgement claimed rollback completion", status)
	}
	if _, _, err := beginMTUViewOperation(a, context.Background(), mtuViewRequest{Request: strings.Repeat("c", 32)}, identity); err == nil {
		t.Fatal("replacement started before old rollback drained")
	}
	recordMTUViewRollback(writer, mtuLiveSnapshot{OriginalMTU: 1420}, nil)
	http.Error(writer, "canceled after captured rollback", http.StatusConflict)
	writer.finish()
	if _, status := read(url); status.Running || !status.Complete || !status.Restored || status.Measured || status.EffectiveMTU != 1420 {
		t.Fatal("completed rollback status was not retained", status)
	}
	if _, _, err := beginMTUViewOperation(a, context.Background(), request, identity); err == nil {
		t.Fatal("completed request ID was replayed")
	}
	newCtx, next, err := beginMTUViewOperation(a, context.Background(), mtuViewRequest{Request: strings.Repeat("c", 32)}, identity)
	if err != nil {
		t.Fatal(err)
	}
	defer next.cancel()
	response := httptest.NewRecorder()
	a.cancelDesktopMTURoute(response, httptest.NewRequest(http.MethodPost, "/api/mtu/cancel", strings.NewReader(`{"request_id":"`+request.Request+`","session_id":"`+identity.Session+`"}`)))
	if response.Code != http.StatusConflict || newCtx.Err() != nil {
		t.Fatal("old cancellation retired a new measurement")
	}
	tracker := sessionTrackerFor(a)
	tracker.mu.Lock()
	tracker.session.ID = "replacement-session"
	tracker.mu.Unlock()
	if response, _ := read(url); response.Code != http.StatusConflict {
		t.Fatal("old poll followed the replacement connection")
	}
}

func TestMTUViewNativeRetestUsesCallerIdentityAndConfirmsRollback(t *testing.T) {
	a, launch := desktopMTUControllerFixture(t, "mtu-hold")
	t.Cleanup(func() { mtuViewSlots.Delete(a); mtuRetestLocks.Delete(a) })
	id := strings.Repeat("c", 32)
	body, _ := json.Marshal(mtuViewRequest{Request: id, Session: launch.external.session, Profile: launch.external.expected.ExitID})
	response := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		defer close(done)
		a.retestMTU(response, httptest.NewRequest(http.MethodPost, "/api/mtu/retest", strings.NewReader(string(body))))
	}()
	record := desktopMTUWaitRecord(t, launch, func(r desktopMTURecord) bool { return r.Status.Request == id && r.Status.Running })
	if record.Status.Request != id {
		t.Fatal("native mailbox substituted the caller's operation ID")
	}
	statusResponse := httptest.NewRecorder()
	a.desktopMTUStatus(statusResponse, httptest.NewRequest(http.MethodGet, "/api/mtu/status?request_id="+id+"&session_id="+launch.external.session, nil))
	var status struct {
		Status  mobilemtu.Status `json:"status"`
		Allowed *bool            `json:"optimization_allowed"`
	}
	if statusResponse.Code != http.StatusOK || json.Unmarshal(statusResponse.Body.Bytes(), &status) != nil || !status.Status.Running || status.Status.Complete || status.Status.Request != id || status.Allowed == nil || !*status.Allowed {
		t.Fatal("native progress not bound to captured request", statusResponse.Code, status)
	}
	cancelResponse := httptest.NewRecorder()
	a.cancelDesktopMTURoute(cancelResponse, httptest.NewRequest(http.MethodPost, "/api/mtu/cancel", strings.NewReader(string(body))))
	if cancelResponse.Code != http.StatusOK {
		t.Fatal("captured native cancellation rejected", cancelResponse.Body.String())
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("native cancellation failed to drain")
	}
	statusResponse = httptest.NewRecorder()
	a.desktopMTUStatus(statusResponse, httptest.NewRequest(http.MethodGet, "/api/mtu/status?request_id="+id+"&session_id="+launch.external.session, nil))
	if statusResponse.Code != http.StatusOK || json.Unmarshal(statusResponse.Body.Bytes(), &status) != nil || status.Status.Running || !status.Status.Complete || !status.Status.Restored || status.Status.Measured || status.Status.Request != id {
		t.Fatal("terminal view did not wait for native rollback", statusResponse.Code, status)
	}
}

func TestMTUViewNativeCompletionRequiresItsExactMeasuredResult(t *testing.T) {
	for _, change := range []string{"valid", "different-request", "different-source", "different-mtu", "incomplete", "still-running", "unmeasured", "missing-result", "http-failure"} {
		t.Run(change, func(t *testing.T) {
			request := strings.Repeat("a", 32)
			operation := &mtuViewOperation{identity: mtuViewIdentity{Session: "captured", Profile: "exit", Native: true}, request: request,
				status: mobilemtu.Status{Request: request, Phase: "verifying", Running: true, Source: "unmeasured"}}
			result := &mobilemtu.Status{Request: request, Complete: true, Measured: true, Phase: "complete", EffectiveMTU: 1380, Source: "measured-public-system-tun-transfer"}
			code := http.StatusOK
			switch change {
			case "different-request":
				result.Request = strings.Repeat("b", 32)
			case "different-source":
				result.Source = "historical-cached"
			case "different-mtu":
				result.EffectiveMTU = 1400
			case "incomplete":
				result.Complete = false
			case "still-running":
				result.Running = true
			case "unmeasured":
				result.Measured = false
			case "missing-result":
				result = nil
			case "http-failure":
				code = http.StatusConflict
			}
			writer := &mtuViewResponse{ResponseWriter: httptest.NewRecorder(), operation: operation}
			writer.WriteHeader(code)
			if err := json.NewEncoder(writer).Encode(map[string]any{"ok": true, "effective_mtu": 1380, "effective_mtu_source": "measured-public-system-tun-transfer", "result": result}); err != nil {
				t.Fatal(err)
			}
			writer.finish()
			status := operation.status
			if status.Request != request || status.Running || !status.Complete || status.Measured != (change == "valid") {
				t.Fatal("view reported a foreign, unfinished or unmeasured result as its own", status)
			}
			if change != "valid" && (status.Phase != "failed" || status.Failure == "") {
				t.Fatal("invalid completion did not retain a terminal failure", status)
			}
		})
	}
}

func TestMTUViewCompletedManualRecordDoesNotHideLaterAutomaticOwner(t *testing.T) {
	a, launch := desktopMTUControllerFixture(t, "mtu-hold")
	t.Cleanup(func() { mtuViewSlots.Delete(a); mtuRetestLocks.Delete(a) })
	identity := mtuViewIdentity{Session: launch.external.session, Profile: launch.external.expected.ExitID, Native: true}
	oldRequest := strings.Repeat("d", 32)
	_, old, err := beginMTUViewOperation(a, context.Background(), mtuViewRequest{Request: oldRequest}, identity)
	if err != nil {
		t.Fatal(err)
	}
	writer := &mtuViewResponse{ResponseWriter: httptest.NewRecorder(), operation: old}
	http.Error(writer, "previous manual view finished", http.StatusConflict)
	writer.finish()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := a.runDesktopExternalMTU(ctx, launch, false); done <- err }()
	record := desktopMTUWaitRecord(t, launch, func(record desktopMTURecord) bool { return record.Status.Running })
	if record.Status.Request == oldRequest {
		t.Fatal("automatic measurement replayed a completed manual request")
	}
	read := func(request string) (*httptest.ResponseRecorder, mobilemtu.Status) {
		t.Helper()
		response := httptest.NewRecorder()
		url := "/api/mtu/status?session_id=" + identity.Session
		if request != "" {
			url += "&request_id=" + request
		}
		a.desktopMTUStatus(response, httptest.NewRequest(http.MethodGet, url, nil))
		var decoded struct {
			Status mobilemtu.Status `json:"status"`
		}
		if response.Code == http.StatusOK && json.Unmarshal(response.Body.Bytes(), &decoded) != nil {
			t.Fatal("invalid status response")
		}
		return response, decoded.Status
	}
	for _, request := range []string{"", record.Status.Request} {
		if response, status := read(request); response.Code != http.StatusOK || status.Request != record.Status.Request || !status.Running || status.Complete {
			t.Fatal("completed manual view concealed the active automatic operation", response.Code, status)
		}
	}
	if response, _ := read(oldRequest); response.Code != http.StatusNotFound {
		t.Fatal("old filtered observer followed the automatic replacement", response.Code)
	}
	cancelResponse := httptest.NewRecorder()
	a.cancelDesktopMTURoute(cancelResponse, httptest.NewRequest(http.MethodPost, "/api/mtu/cancel", strings.NewReader(`{"request_id":"`+oldRequest+`","session_id":"`+identity.Session+`"}`)))
	if cancelResponse.Code != http.StatusConflict {
		t.Fatal("old manual cancel was accepted after automatic replacement")
	}
	select {
	case err := <-done:
		t.Fatal("old manual cancel drained the automatic replacement", err)
	default:
	}
	cancel()
	select {
	case err := <-done:
		if err != context.Canceled {
			t.Fatal("automatic cancellation did not retain its error", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("automatic owner failed to drain")
	}
	if response, status := read(""); response.Code != http.StatusOK || status.Request != record.Status.Request || status.Running || !status.Complete || !status.Restored {
		t.Fatal("completed manual view concealed the later automatic rollback", response.Code, status)
	}
}
