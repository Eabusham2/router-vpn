package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sync"
	"time"

	"router-vpn/internal/common"
	"router-vpn/internal/dnsmeasure"
)

const desktopDNSDraftLifetime = 120 * time.Second

type desktopDNSRequest struct {
	ProfileID    string `json:"profile_id"`
	ProfileToken string `json:"profile_token,omitempty"`
	SessionID    string `json:"session_id"`
	Request      string `json:"request_id"`
	Transport    string `json:"public_transport,omitempty"`
	ResultID     string `json:"result_id,omitempty"`
}

type desktopDNSView struct {
	ProfileID    string            `json:"profile_id"`
	ProfileToken string            `json:"profile_token"`
	SessionID    string            `json:"session_id"`
	Request      string            `json:"request_id"`
	ExpiresInMS  int64             `json:"expires_in_ms"`
	Status       dnsmeasure.Status `json:"status"`
}

type desktopDNSSlot struct {
	mu        sync.Mutex
	session   string
	current   *desktopDNSOperation
	used      map[string]bool
	cancelled map[string]desktopDNSView
}

type desktopDNSSnapshot struct {
	launch       *desktopNodeLaunch
	session      string
	profileID    string
	profileToken string
	stateToken   string
	baseline     string
	entryID      string
	entryToken   string
}

type desktopDNSOperation struct {
	mu          sync.Mutex
	snapshot    desktopDNSSnapshot
	request     string
	transport   string
	status      dnsmeasure.Status
	completedAt time.Time
	invalid     bool
	cancel      context.CancelFunc
	done        chan struct{}
}

func (a *app) desktopDNSFor() *desktopDNSSlot {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.dnsMeasurements == nil {
		a.dnsMeasurements = &desktopDNSSlot{used: map[string]bool{}, cancelled: map[string]desktopDNSView{}}
	}
	return a.dnsMeasurements
}

func captureDesktopDNSSnapshot(a *app) (desktopDNSSnapshot, error) {
	var snapshot desktopDNSSnapshot
	raw, found := desktopNodeOwners.Load(a)
	launch, ok := raw.(*desktopNodeLaunch)
	if !found || !ok {
		return snapshot, errors.New("DNS Retest needs the currently proved external or Tor native runtime")
	}
	identity, err := capturedDesktopDNSRuntime(launch)
	if err != nil {
		return snapshot, err
	}
	if err := a.desktopDNSCurrentProof(launch); err != nil {
		return snapshot, err
	}
	var baseline *desktopMTUSession
	if launch.external != nil {
		if launch.external.profile.External == nil || !desktopExternalNativeProtocol(launch.external.profile.External.Protocol) {
			return snapshot, errors.New("DNS Retest has no supported captured external engine")
		}
		launch.external.mu.Lock()
		baseline = launch.external.mtu
		launch.external.mu.Unlock()
		if baseline == nil {
			return snapshot, errors.New("native DNS has no captured saved source identity")
		}
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	profile, entry, ok := a.dnsPolicySelectionLocked()
	if !ok || !externalDNSProfile(profile) || profile.ID != identity.node {
		return snapshot, errors.New("select the connected external node and its captured entry before DNS Retest")
	}
	if launch.tor != nil {
		if entry.ID != launch.tor.expected.EntryID || profile.MultihopEnabled != (entry.ID != "") || desktopTorSourceIdentityToken(profile) != launch.tor.sourceIdentityToken() || launch.tor.entryCurrentLocked(a) != nil {
			return snapshot, errors.New("Tor DNS Retest belongs to another saved path or policy")
		}
		baseline = &desktopMTUSession{profileToken: mtuProfileSnapshotToken(profile), entryID: entry.ID}
		if entry.ID != "" {
			baseline.entryToken = mtuProfileSnapshotToken(entry)
		}
	} else if entry.ID != launch.external.expected.EntryID {
		return snapshot, errors.New("DNS Retest entry differs from its captured graph")
	}
	snapshot = desktopDNSSnapshot{launch: launch, session: identity.session, profileID: profile.ID, profileToken: dnsPolicySelectionToken(profile, entry), stateToken: mtuStateSnapshotToken(a.state), baseline: baseline.profileToken, entryID: baseline.entryID, entryToken: baseline.entryToken}
	return snapshot, snapshot.currentLocked(a)
}

func (s desktopDNSSnapshot) currentLocked(a *app) error {
	if owner, found := desktopNodeOwners.Load(a); !found || owner != s.launch {
		return errors.New("native DNS process owner changed")
	}
	if a.closing || a.cmd != s.launch.command || !a.state.Connected || a.state.Phase != "connected" || a.state.RouterID != s.profileID || mtuStateSnapshotToken(a.state) != s.stateToken {
		return errors.New("native DNS connection or controller owner changed")
	}
	if speedLabTemporaryPersistenceSuppressed(a) {
		return errors.New("Speed Lab owns this temporary connection")
	}
	if _, busy := speedLabTemporaryOwners.Load(a); busy {
		return errors.New("Speed Lab owns this temporary connection")
	}
	profile, entry, ok := a.dnsPolicySelectionLocked()
	if !ok || profile.ID != s.profileID || dnsPolicySelectionToken(profile, entry) != s.profileToken || mtuProfileSnapshotToken(profile) != s.baseline || entry.ID != s.entryID || entry.ID != "" && mtuProfileSnapshotToken(entry) != s.entryToken {
		return errors.New("selected DNS source, saved entry or policy changed")
	}
	return nil
}

func (s desktopDNSSnapshot) current(a *app) error {
	if err := a.desktopDNSCurrentProof(s.launch); err != nil {
		return err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return s.currentLocked(a)
}

func readDesktopDNSRequest(w http.ResponseWriter, r *http.Request) (desktopDNSRequest, error) {
	var request desktopDNSRequest
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 4096))
	if err != nil || decodeRelayControlJSON(raw, &request) != nil || request.ProfileID == "" || !desktopMTURequestPattern.MatchString(request.SessionID) || !desktopMTURequestPattern.MatchString(request.Request) {
		return request, errors.New("captured profile_id, session_id and fresh request_id are required")
	}
	return request, nil
}

func writeDesktopDNSJSON(w http.ResponseWriter, code int, value any) {
	w.Header().Set("content-type", "application/json")
	w.Header().Set("cache-control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(value)
}

func desktopDNSInitialView(snapshot desktopDNSSnapshot) desktopDNSView {
	session := snapshot.session
	return desktopDNSView{ProfileID: snapshot.profileID, ProfileToken: snapshot.profileToken, SessionID: session, Status: dnsmeasure.Status{Schema: 1, NodeID: snapshot.profileID, SessionID: session, Stage: "idle", Complete: true, Drained: true, Results: []dnsmeasure.Result{}}}
}

func (a *app) desktopDNSMeasurement(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		request := r.URL.Query().Get("request_id")
		if request == "" {
			snapshot, err := captureDesktopDNSSnapshot(a)
			if err != nil {
				http.Error(w, err.Error(), http.StatusConflict)
				return
			}
			if _, err := readDesktopDNSRecord(snapshot.launch); err != nil {
				http.Error(w, "this native package has no proved DNS measurement mailbox", http.StatusConflict)
				return
			}
			writeDesktopDNSJSON(w, http.StatusOK, desktopDNSInitialView(snapshot))
			return
		}
		if !desktopMTURequestPattern.MatchString(request) {
			http.Error(w, "invalid DNS request identity", http.StatusBadRequest)
			return
		}
		slot := a.desktopDNSFor()
		slot.mu.Lock()
		operation := slot.current
		cancelled, hasCancelled := slot.cancelled[request]
		slot.mu.Unlock()
		if operation != nil && operation.request == request {
			writeDesktopDNSJSON(w, http.StatusOK, operation.view(a))
		} else if hasCancelled {
			writeDesktopDNSJSON(w, http.StatusOK, cancelled)
		} else {
			http.Error(w, "DNS request was replaced or is unknown", http.StatusConflict)
		}
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "GET or POST only", http.StatusMethodNotAllowed)
		return
	}
	request, err := readDesktopDNSRequest(w, r)
	if err != nil || request.ProfileToken == "" || request.ResultID != "" || request.Transport != "tcp" && request.Transport != "tls" && request.Transport != "https" {
		http.Error(w, "DNS Retest requires the captured source revision and TCP, DoT or DoH comparison transport", http.StatusBadRequest)
		return
	}
	release, err := a.beginNodeBoundOperation()
	if err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	defer release()
	snapshot, err := captureDesktopDNSSnapshot(a)
	if err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	if request.ProfileID != snapshot.profileID || request.ProfileToken != snapshot.profileToken || request.SessionID != snapshot.session || r.Context().Err() != nil {
		http.Error(w, "DNS source or connection changed before Retest", http.StatusConflict)
		return
	}
	slot := a.desktopDNSFor()
	slot.mu.Lock()
	if previous := slot.current; previous != nil {
		select {
		case <-previous.done:
		default:
			slot.mu.Unlock()
			http.Error(w, "previous DNS workers are still draining", http.StatusConflict)
			return
		}
	}
	if cancelled, exists := slot.cancelled[request.Request]; exists && cancelled.SessionID == request.SessionID || len(slot.cancelled) >= 256 {
		slot.mu.Unlock()
		http.Error(w, "DNS request was cancelled before start or its request budget is exhausted", http.StatusConflict)
		return
	}
	if slot.session != request.SessionID {
		slot.session, slot.used = request.SessionID, map[string]bool{}
	}
	if slot.used[request.Request] || len(slot.used) >= 256 {
		slot.mu.Unlock()
		http.Error(w, "DNS request was cancelled, reused or its session budget is exhausted", http.StatusConflict)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
	operation := &desktopDNSOperation{snapshot: snapshot, request: request.Request, transport: request.Transport, cancel: cancel, done: make(chan struct{}), status: dnsmeasure.Status{Schema: 1, Request: request.Request, NodeID: request.ProfileID, SessionID: request.SessionID, PublicTransport: request.Transport, Stage: "preparing", Results: []dnsmeasure.Result{}}}
	slot.used[request.Request], slot.current = true, operation
	slot.mu.Unlock()
	go a.runDesktopDNSMeasurement(ctx, operation)
	writeDesktopDNSJSON(w, http.StatusAccepted, operation.view(a))
}

func (a *app) runDesktopDNSMeasurement(ctx context.Context, operation *desktopDNSOperation) {
	defer close(operation.done)
	defer operation.cancel()
	releaseMTU, err := a.holdDesktopMTUForMeasurement(ctx)
	var result dnsmeasure.Status
	if err == nil {
		result, err = a.runDesktopDNSNative(ctx, operation)
		// Retain MTU suspension until the exact native workers have drained.
		defer releaseMTU()
	}
	a.mu.Lock()
	if err == nil {
		err = operation.snapshot.currentLocked(a)
	}
	operation.mu.Lock()
	if err == nil && ctx.Err() == nil && !operation.invalid {
		operation.status, operation.completedAt = result, time.Now()
	} else {
		operation.status.Results = []dnsmeasure.Result{}
		operation.status.Stage, operation.status.Failure = "invalidated", "DNS Retest failed or its captured path changed"
		if operation.invalid || errors.Is(err, context.Canceled) {
			operation.status.Stage, operation.status.Failure = "cancelled", "DNS Retest cancelled"
		}
		operation.status.Complete, operation.status.Drained = true, true
	}
	operation.mu.Unlock()
	a.mu.Unlock()
}

func cloneDesktopDNSStatus(status dnsmeasure.Status) dnsmeasure.Status {
	status.Results = append([]dnsmeasure.Result{}, status.Results...)
	for i := range status.Results {
		if median := status.Results[i].Median; median != nil {
			copy := *median
			status.Results[i].Median = &copy
		}
	}
	return status
}

func (o *desktopDNSOperation) update(status dnsmeasure.Status) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.invalid {
		return
	}
	o.status = cloneDesktopDNSStatus(status)
	if status.Complete && status.Drained {
		o.status.Stage, o.status.Complete, o.status.Drained, o.status.Results = "verifying", false, false, []dnsmeasure.Result{}
	}
}

func (o *desktopDNSOperation) draining() {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.status.Stage, o.status.Failure = "draining", "Waiting for the captured native DNS workers and sockets to close"
	o.status.Complete, o.status.Drained, o.status.Results = true, false, []dnsmeasure.Result{}
}

func (o *desktopDNSOperation) invalidate() {
	o.mu.Lock()
	o.invalid, o.completedAt = true, time.Time{}
	o.status.Stage, o.status.Failure, o.status.Results = "cancelled", "DNS request cancelled or its connection replaced", []dnsmeasure.Result{}
	o.cancel()
	o.mu.Unlock()
}

func invalidateDesktopDNSResults(a *app) {
	a.mu.Lock()
	slot := a.dnsMeasurements
	a.mu.Unlock()
	if slot == nil {
		return
	}
	slot.mu.Lock()
	operation := slot.current
	slot.used, slot.cancelled = map[string]bool{}, map[string]desktopDNSView{}
	slot.mu.Unlock()
	if operation != nil {
		operation.invalidate()
	}
}

func (o *desktopDNSOperation) view(a *app) desktopDNSView {
	// A completed result may survive explicit Disconnect, but never a changed
	// physical network, source or entry. A new Connect invalidates it eagerly.
	o.mu.Lock()
	completed := !o.completedAt.IsZero()
	o.mu.Unlock()
	if completed {
		if err := o.draftCurrent(a); err != nil {
			o.invalidate()
		}
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	view := desktopDNSView{ProfileID: o.snapshot.profileID, ProfileToken: o.snapshot.profileToken, SessionID: o.snapshot.session, Request: o.request, Status: cloneDesktopDNSStatus(o.status)}
	if !o.invalid && !o.completedAt.IsZero() {
		view.ExpiresInMS = max(int64(0), (desktopDNSDraftLifetime - time.Since(o.completedAt)).Milliseconds())
	}
	return view
}

func (o *desktopDNSOperation) draftCurrent(a *app) error {
	if !desktopDNSNetworkCurrent(o.snapshot.launch) {
		return errors.New("DNS result belongs to a previous physical network")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return o.draftCurrentLocked(a)
}

func (o *desktopDNSOperation) draftCurrentLocked(a *app) error {
	profile, entry, ok := a.dnsPolicySelectionLocked()
	if a.closing || !ok || profile.ID != o.snapshot.profileID || dnsPolicySelectionToken(profile, entry) != o.snapshot.profileToken {
		return errors.New("DNS result belongs to an old selected source or entry")
	}
	if a.state.Phase == "failed" {
		return errors.New("DNS result was retired by a failed connection or native proof")
	}
	if profileSettingsBusy(a.state.Connected, a.state.Phase) && (a.cmd != o.snapshot.launch.command || !a.state.Connected || a.state.Phase != "connected") {
		return errors.New("a replacement connection invalidated the DNS result")
	}
	if a.state.Connected {
		if owner, found := desktopNodeOwners.Load(a); !found || owner != o.snapshot.launch {
			return errors.New("a replacement native owner invalidated the DNS result")
		}
	}
	return nil
}

func (a *app) cancelDesktopDNSMeasurement(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	request, err := readDesktopDNSRequest(w, r)
	if err != nil || request.Transport != "" || request.ResultID != "" {
		http.Error(w, "captured DNS cancellation identity is required", http.StatusBadRequest)
		return
	}
	slot := a.desktopDNSFor()
	slot.mu.Lock()
	operation := slot.current
	if operation != nil && operation.request == request.Request {
		if operation.snapshot.profileID != request.ProfileID || operation.snapshot.session != request.SessionID {
			slot.mu.Unlock()
			http.Error(w, "DNS cancellation belongs to another connection", http.StatusConflict)
			return
		}
		slot.mu.Unlock()
		operation.invalidate()
		writeDesktopDNSJSON(w, http.StatusAccepted, operation.view(a))
		return
	}
	if cancelled, exists := slot.cancelled[request.Request]; exists && cancelled.ProfileID == request.ProfileID && cancelled.SessionID == request.SessionID {
		slot.mu.Unlock()
		writeDesktopDNSJSON(w, http.StatusOK, cancelled)
		return
	}
	// No operation with this nonce has been admitted. Holding the same slot
	// lock as Start lets us acknowledge that no native work exists and tombstone
	// the queued request even after a disconnect, while another Start is in
	// preflight, or before the panel receives Start's HTTP response.
	if len(slot.cancelled) >= 256 {
		slot.mu.Unlock()
		http.Error(w, "DNS request budget exhausted; queued starts are rejected", http.StatusConflict)
		return
	}
	view := desktopDNSView{ProfileID: request.ProfileID, ProfileToken: request.ProfileToken, SessionID: request.SessionID, Request: request.Request, Status: dnsmeasure.Status{Schema: 1, NodeID: request.ProfileID, SessionID: request.SessionID, Request: request.Request, Stage: "cancelled", Complete: true, Drained: true, Failure: "DNS request cancelled before native work started", Results: []dnsmeasure.Result{}}}
	slot.cancelled[request.Request] = view
	slot.mu.Unlock()
	writeDesktopDNSJSON(w, http.StatusOK, view)
}

func (a *app) desktopDNSOperationFor(request string) (*desktopDNSOperation, error) {
	slot := a.desktopDNSFor()
	slot.mu.Lock()
	defer slot.mu.Unlock()
	if slot.current == nil || slot.current.request != request {
		return nil, errors.New("DNS result was replaced or is unknown")
	}
	return slot.current, nil
}

func (o *desktopDNSOperation) draft(resultID string) (dnsPolicyRequest, int64, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.draftLocked(resultID)
}

func (o *desktopDNSOperation) draftLocked(resultID string) (dnsPolicyRequest, int64, error) {
	remaining := desktopDNSDraftLifetime - time.Since(o.completedAt)
	if o.invalid || o.completedAt.IsZero() || remaining <= 0 || !o.status.Complete || !o.status.Drained || o.status.Stage != "complete" || o.status.Failure != "" {
		return dnsPolicyRequest{}, 0, errors.New("DNS measurement is incomplete, expired or cancelled")
	}
	var chosen *dnsmeasure.Result
	for i := range o.status.Results {
		candidate := &o.status.Results[i]
		if candidate.Kind != "public" || !candidate.Ready || candidate.Median == nil || candidate.Failed != 0 || candidate.Samples != dnsmeasure.Samples {
			continue
		}
		if resultID == candidate.ID {
			chosen = candidate
			break
		}
		if resultID == "fastest" && (chosen == nil || *candidate.Median < *chosen.Median || *candidate.Median == *chosen.Median && candidate.ID < chosen.ID) {
			chosen = candidate
		}
	}
	if chosen == nil {
		return dnsPolicyRequest{}, 0, errors.New("no valid public resolver has three successful current-path samples")
	}
	mode := "custom"
	if chosen.Transport == "tls" {
		mode = "dot"
	} else if chosen.Transport == "https" {
		mode = "doh"
	} else if chosen.Transport != "tcp" {
		return dnsPolicyRequest{}, 0, errors.New("measured DNS transport is unsupported")
	}
	return dnsPolicyRequest{ProfileID: o.snapshot.profileID, ProfileToken: o.snapshot.profileToken, Mode: mode, Protocol: chosen.Transport, Host: chosen.Address, Port: chosen.Port, ServerName: chosen.ServerName, Path: chosen.Path, MeasurementID: o.request, ResultID: chosen.ID}, remaining.Milliseconds(), nil
}

func (a *app) selectDesktopDNSResult(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	request, err := readDesktopDNSRequest(w, r)
	if err != nil || request.ProfileToken == "" || request.ResultID == "" || request.Transport != "" {
		http.Error(w, "captured DNS result and source identity are required", http.StatusBadRequest)
		return
	}
	operation, err := a.desktopDNSOperationFor(request.Request)
	if err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	if request.ProfileID != operation.snapshot.profileID || request.ProfileToken != operation.snapshot.profileToken || request.SessionID != operation.snapshot.session {
		http.Error(w, "DNS result belongs to another source or connection", http.StatusConflict)
		return
	}
	if err := operation.draftCurrent(a); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	draft, remaining, err := operation.draft(request.ResultID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	writeDesktopDNSJSON(w, http.StatusOK, map[string]any{"draft": draft, "expires_in_ms": remaining, "session_id": request.SessionID, "request_id": request.Request})
}

// The caller holds the connection/settings transaction. Only a typed, current
// public result may accompany a measured draft; the six fields must be exact.
func (a *app) captureDesktopDNSDraftRequest(request dnsPolicyRequest, profile, entry common.RouterProfile) (*desktopDNSOperation, error) {
	if request.MeasurementID == "" && request.ResultID == "" {
		return nil, nil
	}
	if !externalDNSProfile(profile) || !desktopMTURequestPattern.MatchString(request.MeasurementID) || request.ResultID == "" {
		return nil, errors.New("invalid measured DNS draft identity")
	}
	operation, err := a.desktopDNSOperationFor(request.MeasurementID)
	if err != nil {
		return nil, err
	}
	if err := operation.draftCurrent(a); err != nil {
		return nil, err
	}
	expected, _, err := operation.draft(request.ResultID)
	if err != nil {
		return nil, err
	}
	if expected != request || request.ProfileID != profile.ID || request.ProfileToken != dnsPolicySelectionToken(profile, entry) {
		return nil, errors.New("measured DNS draft changed its resolver, transport or captured source")
	}
	return operation, nil
}

// Caller holds app.mu and the settings transaction. Cancel, expiry and network
// invalidation are rechecked at the actual persistence boundary, not merely
// when the draft POST was parsed.
func (o *desktopDNSOperation) beginDraftCommitLocked(a *app, request dnsPolicyRequest) (func(), error) {
	if o == nil {
		return func() {}, nil
	}
	if err := o.draftCurrentLocked(a); err != nil {
		return nil, err
	}
	if !desktopDNSNetworkCurrent(o.snapshot.launch) {
		return nil, errors.New("measured DNS draft belongs to an old network")
	}
	o.mu.Lock()
	expected, _, err := o.draftLocked(request.ResultID)
	if err != nil || expected != request {
		o.mu.Unlock()
		return nil, errors.New("measured DNS draft expired, changed or was cancelled before save")
	}
	return o.mu.Unlock, nil
}
