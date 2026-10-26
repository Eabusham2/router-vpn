package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"

	"router-vpn/internal/applexray"
	"router-vpn/internal/mobilemtu"
)

// The view token is also the native mailbox token. A delayed poll or Cancel
// therefore cannot follow whichever measurement happens to be current later.
type mtuViewRequest struct {
	Request string `json:"request_id,omitempty"`
	Session string `json:"session_id,omitempty"`
	Profile string `json:"profile_id,omitempty"`
}

type mtuViewIdentity struct {
	Session string
	Profile string
	Native  bool
}

type mtuViewOperation struct {
	mu             sync.Mutex
	identity       mtuViewIdentity
	request        string
	cancel         context.CancelFunc
	status         mobilemtu.Status
	automatic      bool
	cleanupPending bool
}

type mtuViewSlot struct {
	mu      sync.Mutex
	session string
	used    map[string]bool
	current *mtuViewOperation
}

var mtuViewSlots sync.Map // One bounded record per application, like mtuRetestLocks.

type mtuViewContextKey struct{}

func readMTUViewRequest(w http.ResponseWriter, r *http.Request) (mtuViewRequest, error) {
	var request mtuViewRequest
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1024))
	if err != nil {
		return request, errors.New("MTU request exceeds its bounded input")
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		raw = []byte(`{}`)
	}
	if _, err := applexray.Object(raw); err != nil {
		return request, errors.New("MTU request must contain one unambiguous JSON object")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&request) != nil || request.Request != "" && !desktopMTURequestPattern.MatchString(request.Request) ||
		len(request.Session) > 128 || len(request.Profile) > 128 || strings.ContainsAny(request.Session+request.Profile, "\x00\r\n") {
		return request, errors.New("invalid captured MTU request identity")
	}
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(raw, &fields)
	for _, name := range []string{"request_id", "session_id", "profile_id"} {
		if value, exists := fields[name]; exists && bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return request, errors.New("MTU request identity cannot be null")
		}
	}
	return request, nil
}

func currentMTUViewIdentity(a *app) (mtuViewIdentity, error) {
	if launch := desktopExternalMTULaunch(a); launch != nil {
		if err := a.desktopMeasurementCurrentProof(launch); err != nil && !errors.Is(err, errDesktopTorMTUTransitionPending) {
			return mtuViewIdentity{}, err
		}
		return desktopMeasurementViewIdentity(launch)
	}
	snapshot, err := captureMTURetestSnapshot(a)
	if err != nil {
		return mtuViewIdentity{}, err
	}
	return mtuViewIdentity{Session: snapshot.SessionID, Profile: snapshot.Profile.ID}, nil
}

func mtuViewSlotFor(a *app) *mtuViewSlot {
	slot, _ := mtuViewSlots.LoadOrStore(a, &mtuViewSlot{})
	return slot.(*mtuViewSlot)
}

func beginMTUViewOperation(a *app, parent context.Context, request mtuViewRequest, identity mtuViewIdentity) (context.Context, *mtuViewOperation, error) {
	if identity.Session == "" || identity.Profile == "" || request.Session != "" && request.Session != identity.Session || request.Profile != "" && request.Profile != identity.Profile {
		return nil, nil, errors.New("MTU request belongs to a replaced connection or profile")
	}
	if parent == nil || parent.Err() != nil {
		return nil, nil, errors.New("MTU request was canceled before acceptance")
	}
	if request.Request == "" {
		identifier, err := randomHex(16)
		if err != nil {
			return nil, nil, err
		}
		request.Request = identifier
	}
	if !desktopMTURequestPattern.MatchString(request.Request) {
		return nil, nil, errors.New("invalid MTU request identifier")
	}
	slot := mtuViewSlotFor(a)
	slot.mu.Lock()
	defer slot.mu.Unlock()
	if slot.session != identity.Session {
		slot.session, slot.used = identity.Session, make(map[string]bool)
	}
	if slot.used[request.Request] || len(slot.used) >= 4096 {
		return nil, nil, errors.New("MTU request was already used or this connection reached its bounded request limit")
	}
	if previous := slot.current; previous != nil {
		previous.mu.Lock()
		running := previous.status.Running
		previous.mu.Unlock()
		if running {
			return nil, nil, errors.New("the previous captured MTU operation is still draining")
		}
	}
	ctx, cancel := context.WithCancel(parent)
	operation := &mtuViewOperation{identity: identity, request: request.Request, cancel: cancel,
		status: mobilemtu.Status{Request: request.Request, Phase: "preparing", Running: true, Source: "unmeasured", Candidates: []mobilemtu.Candidate{}}}
	operation.automatic, _ = parent.Value(mtuAutomaticContextKey{}).(bool)
	slot.used[request.Request], slot.current = true, operation
	if attempt, ok := parent.Value(mtuAutomaticContextKey{}).(*mtuAutomaticAttempt); ok {
		operation.automatic = true
		attempt.accepted.Store(true)
	}
	return context.WithValue(ctx, mtuViewContextKey{}, operation), operation, nil
}

func mtuViewOperationFrom(ctx context.Context) *mtuViewOperation {
	operation, _ := ctx.Value(mtuViewContextKey{}).(*mtuViewOperation)
	return operation
}

func updateMTUViewPhase(ctx context.Context, phase string, original int) {
	if operation := mtuViewOperationFrom(ctx); operation != nil {
		operation.mu.Lock()
		if operation.status.Running && operation.status.Phase != "canceling" {
			operation.status.Phase = phase
		}
		if original != 0 {
			operation.status.OriginalMTU, operation.status.EffectiveMTU = original, original
		}
		operation.mu.Unlock()
	}
}

func lookupMTUViewOperation(a *app, identity mtuViewIdentity, request string) *mtuViewOperation {
	raw, ok := mtuViewSlots.Load(a)
	if !ok {
		return nil
	}
	slot := raw.(*mtuViewSlot)
	slot.mu.Lock()
	defer slot.mu.Unlock()
	operation := slot.current
	if operation == nil || operation.identity != identity || request != "" && operation.request != request {
		return nil
	}
	return operation
}

type mtuViewResponse struct {
	http.ResponseWriter
	operation *mtuViewOperation
	code      int
	body      bytes.Buffer
}

func (writer *mtuViewResponse) WriteHeader(code int) {
	if writer.code != 0 {
		return
	}
	writer.code = code
	writer.ResponseWriter.WriteHeader(code)
}

func (writer *mtuViewResponse) Write(data []byte) (int, error) {
	if writer.code == 0 {
		writer.WriteHeader(http.StatusOK)
	}
	if remaining := (64 << 10) - writer.body.Len(); remaining > 0 {
		_, _ = writer.body.Write(data[:min(len(data), remaining)])
	}
	return writer.ResponseWriter.Write(data)
}

func recordMTUViewRollback(w http.ResponseWriter, live mtuLiveSnapshot, failure error) {
	if writer, ok := w.(*mtuViewResponse); ok {
		operation := writer.operation
		operation.mu.Lock()
		operation.status.Restored = failure == nil
		if failure == nil {
			operation.status.EffectiveMTU, operation.status.Source = live.OriginalMTU, "restored-captured-interface"
		}
		operation.mu.Unlock()
	}
}

func (writer *mtuViewResponse) finish() {
	operation := writer.operation
	operation.mu.Lock()
	defer operation.mu.Unlock()
	if operation.cancel != nil {
		operation.cancel()
		operation.cancel = nil
	}
	if operation.cleanupPending {
		operation.status.Running, operation.status.Complete, operation.status.Measured = true, false, false
		operation.status.Phase = "cleanup-pending"
		return
	}
	operation.status.Running, operation.status.Complete = false, true
	var response struct {
		OK        bool              `json:"ok"`
		Effective int               `json:"effective_mtu"`
		Source    string            `json:"effective_mtu_source"`
		Result    *mobilemtu.Status `json:"result"`
	}
	verified := writer.code == http.StatusOK && json.Unmarshal(writer.body.Bytes(), &response) == nil && response.OK && response.Effective >= 576 && response.Effective <= 9000 && response.Source != ""
	if operation.identity.Native {
		verified = verified && response.Result != nil && response.Result.Request == operation.request && response.Result.Complete && response.Result.Measured && !response.Result.Running && response.Result.EffectiveMTU == response.Effective && response.Result.Source == response.Source
	}
	if verified {
		if operation.identity.Native {
			operation.status = *response.Result
		} else {
			operation.status.EffectiveMTU, operation.status.Source = response.Effective, response.Source
			operation.status.Measured = true
		}
		operation.status.Phase = "complete"
		return
	}
	operation.status.Measured = false
	operation.status.Failure = strings.TrimSpace(string(writer.body.Bytes()))
	if len(operation.status.Failure) > 512 {
		operation.status.Failure = operation.status.Failure[:512]
	}
	if operation.status.Failure == "" {
		operation.status.Failure = "MTU operation ended without a verified result"
	}
	operation.status.Phase = "failed"
	if operation.status.Restored {
		operation.status.Phase = "restored"
	}
}

func writeMTUViewStatus(w http.ResponseWriter, identity mtuViewIdentity, requested, waiting, optimizationAllowed bool, status mobilemtu.Status) {
	w.Header().Set("content-type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"session_id": identity.Session, "profile_id": identity.Profile, "requested": requested, "waiting_commit": waiting, "optimization_allowed": optimizationAllowed, "status": status})
}

func (a *app) writeDesktopMTUViewStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}
	query := r.URL.Query()
	request, session := query.Get("request_id"), query.Get("session_id")
	if len(query["request_id"]) > 1 || len(query["session_id"]) > 1 || request != "" && !desktopMTURequestPattern.MatchString(request) || len(session) > 128 {
		http.Error(w, "invalid MTU status identity", http.StatusBadRequest)
		return
	}
	identity, err := currentMTUViewIdentity(a)
	if err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	if session != "" && session != identity.Session {
		http.Error(w, "MTU connection was replaced", http.StatusConflict)
		return
	}
	operation := lookupMTUViewOperation(a, identity, request)
	if operation != nil && identity.Native {
		operation.mu.Lock()
		running := operation.status.Running
		operation.mu.Unlock()
		// A later automatic measurement can start without creating a manual
		// view record. A retained completed view must not conceal that owner.
		if !running {
			if launch := desktopExternalMTULaunch(a); launch != nil && desktopMeasurementSessionMatches(launch, identity.Session) {
				owner := desktopMeasurementMTUSession(launch)
				if owner != nil {
					owner.mu.Lock()
					active := owner.active
					owner.mu.Unlock()
					if active != "" && active != operation.request {
						operation = nil
					}
				}
				if operation != nil {
					if record, err := readDesktopMTURecord(launch); err == nil && record.Status.Request != "" && record.Status.Request != operation.request {
						operation = nil
					}
				}
			}
		}
	}
	if operation != nil {
		operation.mu.Lock()
		status := operation.status
		operation.mu.Unlock()
		waiting := false
		optimizationAllowed := !identity.Native // Legacy capture already validated Router-node Auto.
		if identity.Native {
			if launch := desktopExternalMTULaunch(a); launch != nil && desktopMeasurementSessionMatches(launch, identity.Session) {
				if record, err := readDesktopMTURecord(launch); err == nil {
					optimizationAllowed = record.Requested
					if status.Running && record.Status.Request == operation.request {
						pendingPhase := status.Phase
						status, waiting = record.Status, record.WaitingCommit
						if status.Complete || pendingPhase == "canceling" {
							status.Phase = pendingPhase
						}
						status.Running, status.Complete, status.Measured = true, false, false
					}
				}
			}
		}
		writeMTUViewStatus(w, identity, true, waiting, optimizationAllowed, status)
		return
	}
	if launch := desktopExternalMTULaunch(a); identity.Native && launch != nil && desktopMeasurementSessionMatches(launch, identity.Session) {
		record, err := readDesktopMTURecord(launch)
		if err != nil {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		owner := desktopMeasurementMTUSession(launch)
		if owner != nil {
			owner.mu.Lock()
			active := owner.active
			owner.mu.Unlock()
			if active != "" {
				if record.Status.Request != active {
					record.Status = mobilemtu.Status{Request: active, Phase: "preparing", Source: "unmeasured", Candidates: []mobilemtu.Candidate{}}
				} else if record.Status.Complete {
					record.Status.Phase = "verifying"
				}
				record.Status.Running, record.Status.Complete, record.Status.Measured = true, false, false
			}
		}
		if request != "" && request != record.Status.Request {
			http.Error(w, "MTU request has not started or was replaced", http.StatusNotFound)
			return
		}
		writeMTUViewStatus(w, identity, record.Requested, record.WaitingCommit, record.Requested, record.Status)
		return
	}
	if request != "" {
		http.Error(w, "MTU request has not started or was replaced", http.StatusNotFound)
		return
	}
	snapshot, err := captureMTURetestSnapshot(a)
	if err != nil || snapshot.SessionID != identity.Session {
		http.Error(w, "MTU connection changed while reading status", http.StatusConflict)
		return
	}
	source := "unmeasured"
	if snapshot.Profile.EffectiveMTU > 0 {
		source = "saved-" + snapshot.Profile.EffectiveMTUSource
	}
	writeMTUViewStatus(w, identity, false, false, true, mobilemtu.Status{Phase: "idle", EffectiveMTU: snapshot.Profile.EffectiveMTU, Source: source, Candidates: []mobilemtu.Candidate{}})
}

func cancelMTUViewOperation(a *app, w http.ResponseWriter, request mtuViewRequest) bool {
	raw, found := mtuViewSlots.Load(a)
	if !found {
		return false
	}
	slot := raw.(*mtuViewSlot)
	slot.mu.Lock()
	operation := slot.current
	slot.mu.Unlock()
	if operation == nil || operation.request != request.Request {
		return false
	}
	operation.mu.Lock()
	matches := operation.cancel != nil && operation.status.Running && (request.Session == "" || request.Session == operation.identity.Session) && (request.Profile == "" || request.Profile == operation.identity.Profile)
	if matches {
		operation.status.Phase = "canceling"
		operation.cancel()
	}
	operation.mu.Unlock()
	if !matches {
		http.Error(w, "MTU request already ended or belongs to another view", http.StatusConflict)
		return true
	}
	w.Header().Set("content-type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "request_id": request.Request, "session_id": operation.identity.Session, "phase": "canceling", "note": "Cancellation is pending until the captured rollback finishes."})
	return true
}
