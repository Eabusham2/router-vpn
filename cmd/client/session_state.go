package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"router-vpn/internal/common"
)

type typedSessionError struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	Retryable bool   `json:"retryable"`
}

type dnsProofState struct {
	Mode      string  `json:"mode,omitempty"`
	Host      string  `json:"host,omitempty"`
	LatencyMs float64 `json:"latency_ms,omitempty"`
	Status    string  `json:"status"`
	Reason    string  `json:"reason,omitempty"`
}

type connectionEvent struct {
	Seq       uint64    `json:"seq"`
	At        time.Time `json:"at"`
	Type      string    `json:"type"`
	Phase     string    `json:"phase"`
	Message   string    `json:"message,omitempty"`
	Runtime   string    `json:"runtime_mode,omitempty"`
	Base      string    `json:"base,omitempty"`
	Connected bool      `json:"connected"`
}

type connectionSession struct {
	ID             string             `json:"id"`
	RouterID       string             `json:"router_id,omitempty"`
	RequestedMode  string             `json:"requested_mode,omitempty"`
	RequestedBase  string             `json:"requested_base,omitempty"`
	ActualMode     string             `json:"actual_mode,omitempty"`
	ActualBase     string             `json:"actual_base,omitempty"`
	Engine         string             `json:"engine,omitempty"`
	Phase          string             `json:"phase"`
	Connected      bool               `json:"connected"`
	PathProof      string             `json:"path_proof"`
	RollbackState  string             `json:"rollback_state"`
	StopReason     string             `json:"stop_reason,omitempty"`
	Error          *typedSessionError `json:"error,omitempty"`
	StartedAt      time.Time          `json:"started_at"`
	UpdatedAt      time.Time          `json:"updated_at"`
	EndedAt        *time.Time         `json:"ended_at,omitempty"`
	ExitIP         string             `json:"exit_ip,omitempty"`
	DNSProof       dnsProofState      `json:"dns_proof"`
	Events         []connectionEvent  `json:"events"`
	LastEventSeq   uint64             `json:"last_event_seq"`
}

type observedConnection struct {
	Connected   bool
	Mode        string
	LogicalMode string
	RuntimeMode string
	Base        string
	RouterID    string
	Phase       string
	LastError   string
	Profile     common.RouterProfile
}

type sessionTracker struct {
	a            *app
	mu           sync.Mutex
	session      *connectionSession
	lastKey      string
	requestedMode string
	requestedBase string
	declaredAt   time.Time
	seq          uint64
}

var sessionTrackers sync.Map
var sessionNumber atomic.Uint64

func initSessionTracker(a *app) *sessionTracker {
	if existing, ok := sessionTrackers.Load(a); ok {
		return existing.(*sessionTracker)
	}
	t := &sessionTracker{a: a}
	actual, loaded := sessionTrackers.LoadOrStore(a, t)
	if loaded {
		return actual.(*sessionTracker)
	}
	go t.loop()
	return t
}

func sessionTrackerFor(a *app) *sessionTracker { return initSessionTracker(a) }

func (t *sessionTracker) loop() {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for range ticker.C {
		t.observe(t.capture())
	}
}

func (t *sessionTracker) capture() observedConnection {
	t.a.mu.Lock()
	defer t.a.mu.Unlock()
	s := t.a.state
	p, _ := t.a.profileByIDLocked(t.a.profiles.SelectedID)
	return observedConnection{
		Connected: s.Connected, Mode: s.Mode, LogicalMode: s.LogicalMode,
		RuntimeMode: s.RuntimeMode, Base: s.Base, RouterID: s.RouterID,
		Phase: s.Phase, LastError: s.LastError, Profile: p,
	}
}

func sessionEngine(a *app, runtimeID string) string {
	for _, m := range a.modes {
		if m.ID == runtimeID {
			return m.Engine
		}
	}
	return ""
}

func typedError(message string) *typedSessionError {
	message = strings.TrimSpace(message)
	if message == "" {
		return nil
	}
	lower := strings.ToLower(message)
	code, retryable := "connection_failed", true
	switch {
	case strings.Contains(lower, "path proof"):
		code = "path_proof_failed"
	case strings.Contains(lower, "mode unavailable") || strings.Contains(lower, "unavailable"):
		code = "mode_unavailable"
	case strings.Contains(lower, "no public") || strings.Contains(lower, "endpoint"):
		code = "endpoint_invalid"
		retryable = false
	case strings.Contains(lower, "timeout") || strings.Contains(lower, "timed out"):
		code = "timeout"
	case strings.Contains(lower, "permission") || strings.Contains(lower, "operation not permitted"):
		code = "permission_denied"
		retryable = false
	}
	return &typedSessionError{Code: code, Message: message, Retryable: retryable}
}

func (t *sessionTracker) declareRequest(mode, base string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.requestedMode = strings.TrimSpace(mode)
	t.requestedBase = normalizeBase(base)
	t.declaredAt = time.Now().UTC()
	if t.session == nil || t.session.EndedAt != nil {
		t.startLocked(t.capture(), "requested")
	}
	if t.session != nil {
		t.session.RequestedMode = t.requestedMode
		t.session.RequestedBase = t.requestedBase
		t.session.Phase = "requested"
		t.eventLocked("request", "requested", "connection requested", false, "", "")
	}
}

func (t *sessionTracker) startLocked(s observedConnection, phase string) {
	now := time.Now().UTC()
	id := fmt.Sprintf("session-%d-%d", now.UnixMilli(), sessionNumber.Add(1))
	requested := t.requestedMode
	if requested == "" {
		requested = s.LogicalMode
		if requested == "" {
			requested = s.Mode
		}
	}
	requestedBase := t.requestedBase
	if requestedBase == "" || requestedBase == "auto" {
		requestedBase = normalizeBase(s.Profile.BaseTunnel)
	}
	if requestedBase == "auto" {
		requestedBase = "wg"
	}
	t.session = &connectionSession{
		ID: id, RouterID: s.RouterID, RequestedMode: requested, RequestedBase: requestedBase,
		Phase: phase, PathProof: "not-run", RollbackState: "not-needed",
		StartedAt: now, UpdatedAt: now,
		DNSProof: dnsProofState{Status: "not-proven", Reason: "end-to-end selected-DNS proof has not been established for this session"},
		Events: []connectionEvent{},
	}
	t.lastKey = ""
}

func (t *sessionTracker) observe(s observedConnection) {
	t.mu.Lock()
	defer t.mu.Unlock()
	phase := strings.TrimSpace(s.Phase)
	if phase == "" {
		phase = "off"
	}
	active := phase != "off" && phase != "failed"
	if t.session == nil && active {
		t.startLocked(s, phase)
	} else if t.session != nil && t.session.EndedAt != nil && active {
		t.startLocked(s, phase)
	}
	if t.session == nil {
		return
	}
	// A declared request may sit briefly at old/off state before the handler moves
	// into starting/checking. Do not immediately close it as a zero-length session.
	if t.session.Phase == "requested" && phase == "off" && time.Since(t.declaredAt) < 2*time.Second && s.LastError == "" {
		return
	}

	runtimeID := s.RuntimeMode
	if runtimeID == "" && s.Mode != "off" {
		runtimeID = s.Mode
	}
	logical := s.LogicalMode
	if logical != "" {
		t.session.RequestedMode = logical
	} else if t.session.RequestedMode == "" && s.Mode != "off" {
		t.session.RequestedMode = s.Mode
	}
	t.session.RouterID = s.RouterID
	t.session.ActualMode = runtimeID
	t.session.ActualBase = s.Base
	t.session.Engine = sessionEngine(t.a, runtimeID)
	t.session.Phase = phase
	t.session.Connected = s.Connected
	t.session.Error = typedError(s.LastError)
	t.session.ExitIP = s.Profile.PublicIP
	t.session.DNSProof.Mode = s.Profile.DNSMode
	t.session.DNSProof.Host = s.Profile.DNSHost
	t.session.DNSProof.LatencyMs = s.Profile.FastestDNSLatencyMs
	if s.Connected && phase == "connected" {
		t.session.PathProof = "passed"
	} else if strings.Contains(strings.ToLower(s.LastError), "path proof") {
		t.session.PathProof = "failed"
		t.session.RollbackState = "completed"
	} else if phase == "starting" || phase == "checking" || strings.HasPrefix(phase, "auto:") {
		t.session.PathProof = "pending"
	}
	if phase == "stopping" && t.session.StopReason == "" {
		if t.session.Connected {
			t.session.StopReason = "user-or-mode-switch"
		} else {
			t.session.StopReason = "rollback-or-mode-switch"
		}
	}
	now := time.Now().UTC()
	t.session.UpdatedAt = now
	key := fmt.Sprintf("%t|%s|%s|%s|%s|%s|%s|%s", s.Connected, phase, s.Mode, logical, runtimeID, s.Base, s.RouterID, s.LastError)
	if key != t.lastKey {
		kind, message := "phase", ""
		switch {
		case s.Connected && phase == "connected":
			kind, message = "connected", "selected-router path proof passed"
		case phase == "failed":
			kind, message = "failed", s.LastError
		case phase == "stopping":
			kind, message = "stopping", t.session.StopReason
		}
		t.eventLocked(kind, phase, message, s.Connected, runtimeID, s.Base)
		t.lastKey = key
	}
	if (phase == "off" || phase == "failed") && t.session.EndedAt == nil {
		end := now
		t.session.EndedAt = &end
	}
}

func (t *sessionTracker) eventLocked(kind, phase, message string, connected bool, runtimeID, base string) {
	t.seq++
	e := connectionEvent{Seq: t.seq, At: time.Now().UTC(), Type: kind, Phase: phase, Message: message, Connected: connected, Runtime: runtimeID, Base: base}
	t.session.Events = append(t.session.Events, e)
	if len(t.session.Events) > 256 {
		t.session.Events = append([]connectionEvent(nil), t.session.Events[len(t.session.Events)-256:]...)
	}
	t.session.LastEventSeq = t.seq
	t.session.UpdatedAt = e.At
}

func (t *sessionTracker) markStopReason(reason string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.session != nil {
		t.session.StopReason = reason
		t.eventLocked("stop-request", t.session.Phase, reason, t.session.Connected, t.session.ActualMode, t.session.ActualBase)
	}
}

func (t *sessionTracker) markRequestFailure(message string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.session == nil || t.session.EndedAt != nil {
		return
	}
	now := time.Now().UTC()
	t.session.Error = typedError(message)
	t.session.Phase = "failed"
	t.session.Connected = false
	t.session.EndedAt = &now
	t.eventLocked("failed", "failed", message, false, t.session.ActualMode, t.session.ActualBase)
}

func (t *sessionTracker) snapshot(after uint64) connectionSession {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.session == nil {
		return connectionSession{Phase: "off", PathProof: "not-run", RollbackState: "not-needed", DNSProof: dnsProofState{Status: "not-proven"}, Events: []connectionEvent{}}
	}
	out := *t.session
	out.Events = append([]connectionEvent(nil), t.session.Events...)
	if after > 0 {
		filtered := out.Events[:0]
		for _, e := range out.Events {
			if e.Seq > after {
				filtered = append(filtered, e)
			}
		}
		out.Events = filtered
	}
	return out
}

func (a *app) sessionStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("content-type", "application/json")
	_ = json.NewEncoder(w).Encode(sessionTrackerFor(a).snapshot(0))
}

func (a *app) sessionEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}
	var after uint64
	_, _ = fmt.Sscan(r.URL.Query().Get("after"), &after)
	s := sessionTrackerFor(a).snapshot(after)
	w.Header().Set("content-type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"session_id": s.ID, "phase": s.Phase, "last_event_seq": s.LastEventSeq, "events": s.Events})
}

type statusCapturingWriter struct {
	http.ResponseWriter
	status int
	body   bytes.Buffer
}

func (w *statusCapturingWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}
func (w *statusCapturingWriter) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	if w.status >= 400 && w.body.Len() < 4096 {
		_, _ = w.body.Write(p[:min(len(p), 4096-w.body.Len())])
	}
	return w.ResponseWriter.Write(p)
}

func (a *app) connectLogicalTracked(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, (16<<10)+1))
	if err != nil || len(body) > 16<<10 {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	var q struct {
		Mode string `json:"mode"`
		Base string `json:"base"`
	}
	if err := json.Unmarshal(body, &q); err == nil && strings.TrimSpace(q.Mode) != "" {
		sessionTrackerFor(a).declareRequest(q.Mode, q.Base)
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	cw := &statusCapturingWriter{ResponseWriter: w}
	a.connectLogical(cw, r)
	if cw.status >= 400 {
		message := strings.TrimSpace(cw.body.String())
		if message == "" {
			message = http.StatusText(cw.status)
		}
		sessionTrackerFor(a).markRequestFailure(message)
	}
}

func (a *app) emergencyStopTracked(w http.ResponseWriter, r *http.Request) {
	sessionTrackerFor(a).markStopReason("emergency-stop")
	a.emergencyStop(w, r)
}
