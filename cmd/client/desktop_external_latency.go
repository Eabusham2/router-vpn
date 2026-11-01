package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sync"
	"time"

	"router-vpn/internal/hopmeasure"
)

type desktopLatencyRequest struct {
	ProfileID    string `json:"profile_id"`
	ProfileToken string `json:"profile_token,omitempty"`
	SessionID    string `json:"session_id"`
	Request      string `json:"request_id"`
}

type desktopLatencyView struct {
	ProfileID     string            `json:"profile_id"`
	ProfileToken  string            `json:"profile_token"`
	SessionID     string            `json:"session_id"`
	Request       string            `json:"request_id"`
	SourceSHA256  string            `json:"source_sha256"`
	ConfigSHA256  string            `json:"config_sha256"`
	NetworkSHA256 string            `json:"network_sha256"`
	MeasuredAt    int64             `json:"measured_at,omitempty"`
	Status        hopmeasure.Status `json:"status"`
}

type desktopLatencySlot struct {
	mu           sync.Mutex
	session      string
	profileID    string
	profileToken string
	current      *desktopLatencyOperation
	used         map[string]bool
	cancelled    map[string]desktopLatencyView
}

type desktopLatencySnapshot = desktopDNSSnapshot

type desktopLatencyOperation struct {
	mu          sync.Mutex
	snapshot    desktopLatencySnapshot
	request     string
	status      hopmeasure.Status
	completedAt time.Time
	invalid     bool
	cancel      context.CancelFunc
	done        chan struct{}
}

func (a *app) desktopLatencyFor() *desktopLatencySlot {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.latencyMeasurements == nil {
		a.latencyMeasurements = &desktopLatencySlot{used: map[string]bool{}, cancelled: map[string]desktopLatencyView{}}
	}
	return a.latencyMeasurements
}

// Reuse the exact saved-source/native-session witness used by selected DNS.
// This public operation deliberately rejects temporary Speed Lab sessions;
// later batch composition must borrow its own explicit transaction authority.
func captureDesktopLatencySnapshot(a *app) (desktopLatencySnapshot, error) {
	return captureDesktopDNSSnapshot(a)
}

func readDesktopLatencyRequest(w http.ResponseWriter, r *http.Request) (desktopLatencyRequest, error) {
	var request desktopLatencyRequest
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 4096))
	if err != nil || decodeRelayControlJSON(raw, &request) != nil || request.ProfileID == "" || !desktopMTURequestPattern.MatchString(request.SessionID) || !desktopMTURequestPattern.MatchString(request.Request) {
		return request, errors.New("captured profile_id, session_id and fresh request_id are required")
	}
	return request, nil
}

func writeDesktopLatencyJSON(w http.ResponseWriter, code int, value any) {
	w.Header().Set("content-type", "application/json")
	w.Header().Set("cache-control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(value)
}

func desktopLatencyInitialView(snapshot desktopLatencySnapshot) desktopLatencyView {
	identity, _ := capturedDesktopLatencyRuntime(snapshot.launch)
	return desktopLatencyView{ProfileID: snapshot.profileID, ProfileToken: snapshot.profileToken, SessionID: snapshot.session,
		SourceSHA256: identity.source, ConfigSHA256: identity.config, NetworkSHA256: identity.network,
		Status: hopmeasure.Status{Stage: "idle", Complete: true, Drained: true, Results: []hopmeasure.Result{}}}
}

func (a *app) desktopLatencyMeasurement(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		request := r.URL.Query().Get("request_id")
		if request == "" {
			snapshot, err := captureDesktopLatencySnapshot(a)
			if err != nil {
				http.Error(w, err.Error(), http.StatusConflict)
				return
			}
			if _, err := readDesktopLatencyRecord(snapshot.launch); err != nil {
				http.Error(w, "this native package has no proved Latency measurement mailbox", http.StatusConflict)
				return
			}
			writeDesktopLatencyJSON(w, http.StatusOK, desktopLatencyInitialView(snapshot))
			return
		}
		if !desktopMTURequestPattern.MatchString(request) {
			http.Error(w, "invalid Latency request identity", http.StatusBadRequest)
			return
		}
		slot := a.desktopLatencyFor()
		slot.mu.Lock()
		operation := slot.current
		cancelled, hasCancelled := slot.cancelled[request]
		slot.mu.Unlock()
		if operation != nil && operation.request == request {
			writeDesktopLatencyJSON(w, http.StatusOK, operation.view(a))
		} else if hasCancelled {
			writeDesktopLatencyJSON(w, http.StatusOK, cancelled)
		} else {
			http.Error(w, "Latency request was replaced or is unknown", http.StatusConflict)
		}
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "GET or POST only", http.StatusMethodNotAllowed)
		return
	}
	request, err := readDesktopLatencyRequest(w, r)
	if err != nil || request.ProfileToken == "" {
		http.Error(w, "Latency Retest requires the captured saved-source revision", http.StatusBadRequest)
		return
	}
	release, err := a.beginNodeBoundOperation()
	if err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	defer release()
	snapshot, err := captureDesktopLatencySnapshot(a)
	if err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	if request.ProfileID != snapshot.profileID || request.ProfileToken != snapshot.profileToken || request.SessionID != snapshot.session || r.Context().Err() != nil {
		http.Error(w, "Latency source or connection changed before Retest", http.StatusConflict)
		return
	}
	slot := a.desktopLatencyFor()
	slot.mu.Lock()
	if previous := slot.current; previous != nil {
		select {
		case <-previous.done:
		default:
			slot.mu.Unlock()
			http.Error(w, "previous Latency workers are still draining", http.StatusConflict)
			return
		}
	}
	// A new, re-proved native session cannot accept old-session requests. Its
	// bounded tombstones therefore need not exhaust the controller lifetime.
	// A queued cancellation may already have installed this same session.
	if slot.session != request.SessionID {
		slot.session, slot.used, slot.cancelled = request.SessionID, map[string]bool{}, map[string]desktopLatencyView{}
		slot.profileID, slot.profileToken = snapshot.profileID, snapshot.profileToken
	}
	if slot.profileID != request.ProfileID || slot.profileToken != request.ProfileToken {
		slot.mu.Unlock()
		http.Error(w, "Latency session belongs to another captured saved source", http.StatusConflict)
		return
	}
	if cancelled, exists := slot.cancelled[request.Request]; exists && cancelled.SessionID == request.SessionID || len(slot.cancelled) >= 256 {
		slot.mu.Unlock()
		http.Error(w, "Latency request was cancelled before start or its request budget is exhausted", http.StatusConflict)
		return
	}
	if slot.used[request.Request] || len(slot.used) >= 256 {
		slot.mu.Unlock()
		http.Error(w, "Latency request was cancelled, reused or its session budget is exhausted", http.StatusConflict)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
	operation := &desktopLatencyOperation{snapshot: snapshot, request: request.Request, cancel: cancel, done: make(chan struct{}), status: hopmeasure.Status{Request: request.Request, Stage: "preparing", Results: []hopmeasure.Result{}}}
	slot.used[request.Request], slot.current = true, operation
	slot.mu.Unlock()
	go a.runDesktopLatencyMeasurement(ctx, operation)
	writeDesktopLatencyJSON(w, http.StatusAccepted, operation.view(a))
}

func (a *app) runDesktopLatencyMeasurement(ctx context.Context, operation *desktopLatencyOperation) {
	defer close(operation.done)
	defer operation.cancel()
	finish, err := beginSpeedLabRun(a)
	var result hopmeasure.Status
	if err == nil {
		defer finish()
		releaseMTU, holdErr := a.holdDesktopMTUForMeasurement(ctx)
		err = holdErr
		if err == nil {
			defer releaseMTU() // after exact worker/socket drain and result adoption
			result, err = a.runDesktopLatencyNative(ctx, operation)
		}
	}
	if err == nil {
		err = operation.snapshot.current(a)
	}
	a.mu.Lock()
	if err == nil {
		err = operation.snapshot.currentLocked(a)
	}
	operation.mu.Lock()
	if err == nil && ctx.Err() == nil && !operation.invalid {
		operation.status, operation.completedAt = cloneDesktopLatencyStatus(result), time.Now()
	} else {
		operation.status.Results = []hopmeasure.Result{}
		operation.status.Stage, operation.status.Failure = "invalidated", "Latency Retest failed or its captured path changed; no score was saved"
		if operation.invalid || errors.Is(err, context.Canceled) {
			operation.status.Stage, operation.status.Failure = "cancelled", "Latency Retest cancelled"
		}
		operation.status.Complete, operation.status.Drained = true, true
	}
	operation.mu.Unlock()
	a.mu.Unlock()
}

func cloneDesktopLatencyStatus(status hopmeasure.Status) hopmeasure.Status {
	status.Results = append([]hopmeasure.Result{}, status.Results...)
	for index := range status.Results {
		if original := status.Results[index].Benchmark; original != nil {
			copy := *original
			if original.Distribution != nil {
				value := *original.Distribution
				copy.Distribution = &value
			}
			status.Results[index].Benchmark = &copy
		}
	}
	return status
}

func (o *desktopLatencyOperation) update(status hopmeasure.Status) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.invalid {
		return
	}
	o.status = cloneDesktopLatencyStatus(status)
	// A native completed result can precede its worker's final release/close.
	// Keep every statistic private until runDesktopLatencyNative confirms
	// drain and the controller revalidates the captured path under its lease.
	o.status.Results = []hopmeasure.Result{}
	if status.Complete {
		o.status.Stage, o.status.Complete, o.status.Drained, o.status.Results = "verifying", false, false, []hopmeasure.Result{}
	}
}

func (o *desktopLatencyOperation) draining() {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.status.Stage, o.status.Failure = "draining", "Waiting for the captured native Latency workers and sockets to close"
	o.status.Complete, o.status.Drained, o.status.Results = true, false, []hopmeasure.Result{}
}

func (o *desktopLatencyOperation) invalidate() {
	o.mu.Lock()
	o.invalid, o.completedAt = true, time.Time{}
	o.status.Stage, o.status.Failure, o.status.Results = "cancelled", "Latency request cancelled or its connection replaced", []hopmeasure.Result{}
	o.cancel()
	o.mu.Unlock()
}

func invalidateDesktopLatencyResults(a *app) {
	a.mu.Lock()
	slot := a.latencyMeasurements
	a.mu.Unlock()
	if slot == nil {
		return
	}
	slot.mu.Lock()
	operation := slot.current
	slot.mu.Unlock()
	if operation != nil {
		operation.invalidate()
	}
}

func (o *desktopLatencyOperation) view(a *app) desktopLatencyView {
	// Successful measurements remain a current-path capability. Historical
	// rankings and batch adoption are separate transactions, not this view.
	o.mu.Lock()
	complete := !o.completedAt.IsZero()
	o.mu.Unlock()
	if complete && o.snapshot.current(a) != nil {
		o.invalidate()
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	view := desktopLatencyInitialView(o.snapshot)
	view.Request, view.Status = o.request, cloneDesktopLatencyStatus(o.status)
	if !o.invalid && !o.completedAt.IsZero() {
		view.MeasuredAt = o.completedAt.UnixMilli()
	}
	return view
}

func (a *app) cancelDesktopLatencyMeasurement(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	request, err := readDesktopLatencyRequest(w, r)
	if err != nil || request.ProfileToken == "" {
		http.Error(w, "captured Latency cancellation identity is required", http.StatusBadRequest)
		return
	}
	// The captured current path may admit a queued cancellation for a new
	// native session. A foreign request cannot rotate the bounded registry.
	snapshot, snapshotErr := captureDesktopLatencySnapshot(a)
	slot := a.desktopLatencyFor()
	a.mu.Lock()
	slot.mu.Lock()
	operation := slot.current
	if operation != nil && operation.request == request.Request {
		if operation.snapshot.profileID != request.ProfileID || operation.snapshot.session != request.SessionID || operation.snapshot.profileToken != request.ProfileToken {
			slot.mu.Unlock()
			a.mu.Unlock()
			http.Error(w, "Latency cancellation belongs to another connection", http.StatusConflict)
			return
		}
		slot.mu.Unlock()
		a.mu.Unlock()
		operation.invalidate()
		writeDesktopLatencyJSON(w, http.StatusAccepted, operation.view(a))
		return
	}
	if cancelled, exists := slot.cancelled[request.Request]; exists && cancelled.ProfileID == request.ProfileID && cancelled.SessionID == request.SessionID && cancelled.ProfileToken == request.ProfileToken {
		slot.mu.Unlock()
		a.mu.Unlock()
		writeDesktopLatencyJSON(w, http.StatusOK, cancelled)
		return
	}
	if slot.session != request.SessionID {
		if snapshotErr != nil || snapshot.session != request.SessionID || snapshot.profileID != request.ProfileID || snapshot.profileToken != request.ProfileToken || snapshot.currentLocked(a) != nil {
			slot.mu.Unlock()
			a.mu.Unlock()
			http.Error(w, "queued latency cancellation belongs to another current native session", http.StatusConflict)
			return
		}
		slot.session, slot.used, slot.cancelled = request.SessionID, map[string]bool{}, map[string]desktopLatencyView{}
		slot.profileID, slot.profileToken = snapshot.profileID, snapshot.profileToken
	}
	if slot.profileID != request.ProfileID || slot.profileToken != request.ProfileToken {
		slot.mu.Unlock()
		a.mu.Unlock()
		http.Error(w, "queued latency cancellation belongs to another captured saved source", http.StatusConflict)
		return
	}
	// No operation with this nonce has been admitted. Holding the same slot
	// lock as Start lets us acknowledge that no native work exists and tombstone
	// the queued request even after a disconnect, while another Start is in
	// preflight, or before the panel receives Start's HTTP response.
	if len(slot.cancelled) >= 256 {
		slot.mu.Unlock()
		a.mu.Unlock()
		http.Error(w, "Latency request budget exhausted; queued starts are rejected", http.StatusConflict)
		return
	}
	view := desktopLatencyView{ProfileID: request.ProfileID, ProfileToken: request.ProfileToken, SessionID: request.SessionID, Request: request.Request, Status: hopmeasure.Status{Request: request.Request, Stage: "cancelled", Complete: true, Drained: true, Failure: "Latency request cancelled before native work started", Results: []hopmeasure.Result{}}}
	slot.cancelled[request.Request] = view
	slot.mu.Unlock()
	a.mu.Unlock()
	writeDesktopLatencyJSON(w, http.StatusOK, view)
}
