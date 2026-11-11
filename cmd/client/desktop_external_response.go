package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"router-vpn/internal/desktopnetwork"
	"router-vpn/internal/hopmeasure"
)

const desktopResponseLifetime = 10 * time.Second
const desktopResponseRefresh = 5 * time.Second

func desktopResponseNetworkDigest(network string) string {
	sum := sha256.Sum256([]byte(network))
	return hex.EncodeToString(sum[:])
}

func desktopResponseRequestID(session, source, config, node string, generation uint64) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("routervpn-live-response-v1\x00%s\x00%s\x00%s\x00%s\x00%d", session, source, config, node, generation)))
	return fmt.Sprintf("%016x", generation) + hex.EncodeToString(sum[:8])
}

func desktopIsResponseRequestID(request, session, source, config, node string) bool {
	if len(request) != 32 {
		return false
	}
	generation, err := strconv.ParseUint(request[:16], 16, 64)
	return err == nil && generation > 0 && request == desktopResponseRequestID(session, source, config, node, generation)
}

func desktopResponseMTUIdle(record desktopMTURecord) bool {
	untouched := record.Generation == 0 && record.Status.Request == "" && record.Status.Phase == "idle" && record.Status.Source == "configured-unmeasured" && record.Status.OriginalMTU == 0
	return !record.Status.Running && !record.WaitingCommit && record.Status.EffectiveMTU > 0 && (record.Status.Complete || untouched)
}

// This current-path value deliberately has no generic median_ms: the native
// clients must recognize the HTTPS type rather than label it private-node RTT.
type desktopResponseView struct {
	Connected     bool                     `json:"connected"`
	ProfileID     string                   `json:"profile_id"`
	ProfileToken  string                   `json:"profile_token"`
	SessionID     string                   `json:"session_id"`
	Request       string                   `json:"request_id"`
	SourceSHA256  string                   `json:"source_sha256"`
	ConfigSHA256  string                   `json:"config_sha256"`
	NetworkSHA256 string                   `json:"network_sha256"`
	MeasuredAt    int64                    `json:"measured_at"`
	ExpiresInMS   int64                    `json:"expires_in_ms"`
	Measurement   string                   `json:"measurement"`
	Response      *hopmeasure.PathResponse `json:"response,omitempty"`
	Proof         string                   `json:"proof"`
}

func desktopExternalResponseSelected(a *app) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	profile, ok := a.profileByIDLocked(a.state.RouterID)
	return ok && (profile.External != nil || profile.NodeKind == "external")
}

func desktopResponseNativePhase(stage string) bool {
	const prefix = "exit: live HTTPS response "
	if !strings.HasPrefix(stage, prefix) || !strings.HasSuffix(stage, "/3") {
		return false
	}
	text := strings.TrimSuffix(strings.TrimPrefix(stage, prefix), "/3")
	n, err := strconv.Atoi(text)
	return err == nil && n >= 1 && n <= hopmeasure.PathResponseSamples && strconv.Itoa(n) == text
}

func validateDesktopResponseResults(launch *desktopNodeLaunch, status hopmeasure.Status) error {
	bad := errors.New("no complete drained three-response HTTPS result for the captured exit")
	owner, err := capturedDesktopLatencyRuntime(launch)
	if err != nil || !status.Complete || !status.Drained || status.Stage != "complete" || status.Failure != "" || len(status.Results) != 1 {
		return bad
	}
	row := status.Results[0]
	r := row.Response
	if !row.Ready || row.Failure != "" || row.ID != owner.node || row.Role != "exit" || row.Kind != "public-path" || row.Label != "External exit → Cloudflare edge" || row.Benchmark != nil || row.Idle != nil || row.Download != nil || row.Upload != nil || r == nil {
		return bad
	}
	if r.Schema != 1 || r.Measurement != "routed-https-response-after-tls" || r.Endpoint != "https://"+hopmeasure.PublicHost+"/__down?bytes=1" || r.Attempts != hopmeasure.PathResponseSamples || r.Distribution == nil {
		return bad
	}
	d := r.Distribution
	if d.Samples != hopmeasure.PathResponseSamples {
		return bad
	}
	for _, value := range []float64{d.Min, d.Median, d.Average, d.P90, d.Max} {
		if math.IsNaN(value) || math.IsInf(value, 0) || value <= 0 || value > 10000 || value < d.Min || value > d.Max {
			return bad
		}
	}
	if d.Min > d.Median || d.Median > d.P90 || d.P90 > d.Max || math.IsNaN(d.Jitter) || math.IsInf(d.Jitter, 0) || d.Jitter < 0 || d.Jitter > d.Max-d.Min {
		return bad
	}
	return nil
}

// Unlike an explicit Speed Lab action this reservation never cancels MTU. The
// same suspension and start mutex make idle observation atomic with Auto and
// Retest. Nested connection cleanup may share the already-idle hold.
func (a *app) holdDesktopResponseMTU(ctx context.Context, operation *desktopLatencyOperation) (func(), error) {
	if err := operation.snapshot.currentContext(ctx, a); err != nil {
		return nil, err
	}
	launch := operation.snapshot.launch
	owner := desktopMeasurementMTUSession(launch)
	if owner == nil {
		return nil, errors.New("live HTTPS has no captured MTU session")
	}
	suspension := mtuSuspensionFor(a)
	if err := desktopnetwork.LockContext(ctx, &suspension.mu); err != nil {
		return nil, err
	}
	lock := mtuRetestLockFor(a)
	if suspension.users != 0 || !lock.TryLock() {
		suspension.mu.Unlock()
		return nil, errors.New("live HTTPS waits for the current MTU operation")
	}
	ready := make(chan struct{})
	close(ready)
	suspension.users, suspension.ready, suspension.held, suspension.failure = 1, ready, true, nil
	suspension.mu.Unlock()
	var once sync.Once
	release := func() {
		once.Do(func() {
			suspension.mu.Lock()
			if suspension.ready != ready || suspension.users <= 0 {
				suspension.mu.Unlock()
				return
			}
			suspension.users--
			last := suspension.users == 0
			if last {
				lock.Unlock()
				suspension.held, suspension.ready = false, nil
			}
			suspension.mu.Unlock()
			// A failed/cancelled HTTPS sample cannot strand first Auto. It also
			// cannot resume an MTU owner installed by a replacement connection.
			if last && desktopMeasurementMTUSession(launch) == owner && operation.snapshot.current(a) == nil {
				a.startDesktopExternalAutomaticMTU(launch)
			}
		})
	}
	record, err := readDesktopMTURecordContext(ctx, launch)
	if err != nil || !desktopResponseMTUIdle(record) || desktopMeasurementMTUSession(launch) != owner {
		release()
		return nil, errors.New("live HTTPS waits for verified idle native MTU")
	}
	operation.mu.Lock()
	operation.responseMTU, operation.responseMTUGeneration = owner, record.Generation
	operation.mu.Unlock()
	return release, nil
}

func (o *desktopLatencyOperation) responseView(a *app) desktopResponseView {
	identity, _ := capturedDesktopLatencyRuntime(o.snapshot.launch)
	view := desktopResponseView{Connected: true, ProfileID: o.snapshot.profileID, ProfileToken: o.snapshot.profileToken, SessionID: o.snapshot.session, Request: o.request,
		SourceSHA256: identity.source, ConfigSHA256: identity.config, NetworkSHA256: desktopResponseNetworkDigest(identity.network), Measurement: "routed-https-response-after-tls",
		Proof: "Three current-path HTTPS responses after routed DNS, TCP and TLS preparation; expires after ten seconds. Separate from private-node HTTP RTT, ICMP and saved50 benchmarks."}
	if o.snapshot.current(a) != nil {
		o.invalidate()
		return view
	}
	o.mu.Lock()
	status, completed, invalid, owner, generation := cloneDesktopLatencyStatus(o.status), o.completedAt, o.invalid, o.responseMTU, o.responseMTUGeneration
	o.mu.Unlock()
	age := time.Since(completed)
	if !o.responseOnly || invalid || completed.IsZero() || age < 0 || age >= desktopResponseLifetime || owner == nil || desktopMeasurementMTUSession(o.snapshot.launch) != owner || validateDesktopResponseResults(o.snapshot.launch, status) != nil {
		return view
	}
	mtu, err := readDesktopMTURecord(o.snapshot.launch)
	if err != nil || mtu.Generation != generation || !desktopResponseMTUIdle(mtu) || o.snapshot.current(a) != nil {
		return view
	}
	age = time.Since(completed)
	if age < 0 || age >= desktopResponseLifetime {
		return view
	}
	view.MeasuredAt, view.ExpiresInMS, view.Response = completed.UnixMilli(), (desktopResponseLifetime - age).Milliseconds(), status.Results[0].Response
	return view
}

// Polling never blocks a native UI for the ten-second worker budget. Only the
// original captured operation may populate this ephemeral value; pending and
// expired replies contain no score. Disconnect uses the existing latency
// invalidation owner and the native generation remains held through drain.
func (a *app) connectionExternalLiveResponse(w http.ResponseWriter, r *http.Request) {
	validateOnly := r.URL.Query().Get("request_id")
	if len(r.URL.Query()) != 0 && (r.Method != http.MethodGet || len(r.URL.Query()) != 1 || len(r.URL.Query()["request_id"]) != 1 || !desktopMTURequestPattern.MatchString(validateOnly)) {
		http.Error(w, "invalid live response receipt", http.StatusBadRequest)
		return
	}
	release, err := a.beginNodeBoundOperation()
	if err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	defer release()
	snapshot, err := captureDesktopLatencySnapshot(a)
	if err != nil || r.Context().Err() != nil {
		http.Error(w, "current external response path is unavailable", http.StatusConflict)
		return
	}
	slot := a.desktopLatencyFor()
	slot.mu.Lock()
	previous := slot.response
	manual := slot.current
	slot.mu.Unlock()
	var previousView desktopResponseView
	if previous != nil {
		previousView = previous.responseView(a)
	}
	slot.mu.Lock()
	defer slot.mu.Unlock()
	if slot.response != previous || slot.current != manual {
		http.Error(w, "measurement owner changed", http.StatusConflict)
		return
	}
	if validateOnly != "" {
		if previous == nil || previous.request != validateOnly || previousView.Response == nil {
			http.Error(w, "live response expired or its captured owner changed", http.StatusConflict)
			return
		}
		writeDesktopLatencyJSON(w, http.StatusOK, previousView)
		return
	}
	if time.Now().Before(slot.responsePauseUntil) {
		http.Error(w, "automatic HTTPS responses are paused for the explicit measurement", http.StatusConflict)
		return
	}
	if manual != nil {
		select {
		case <-manual.done:
		default:
			http.Error(w, "live HTTPS waits for the selected benchmark", http.StatusConflict)
			return
		}
	}
	if previous != nil {
		select {
		case <-previous.done:
		default:
			writeDesktopLatencyJSON(w, http.StatusAccepted, previousView)
			return
		}
		if time.Since(previous.startedAt) < desktopResponseRefresh && previous.snapshot.session == snapshot.session && previous.snapshot.profileToken == snapshot.profileToken {
			code := http.StatusAccepted
			if previousView.Response != nil {
				code = http.StatusOK
			}
			writeDesktopLatencyJSON(w, code, previousView)
			return
		}
	}
	owner, err := capturedDesktopLatencyRuntime(snapshot.launch)
	if err != nil || !owner.lock.TryLock() {
		http.Error(w, "live response identity unavailable", http.StatusInternalServerError)
		return
	}
	request := desktopResponseRequestID(owner.session, owner.source, owner.config, owner.node, *owner.generation+1)
	owner.lock.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	operation := &desktopLatencyOperation{snapshot: snapshot, request: request, cancel: cancel, done: make(chan struct{}), responseOnly: true, startedAt: time.Now(), status: hopmeasure.Status{Request: request, Stage: "preparing", Results: []hopmeasure.Result{}}}
	slot.response = operation
	go a.runDesktopLatencyMeasurement(ctx, operation)
	// No responseView call while slot.mu is held: source validation takes a.mu.
	identity, _ := capturedDesktopLatencyRuntime(snapshot.launch)
	writeDesktopLatencyJSON(w, http.StatusAccepted, desktopResponseView{Connected: true, ProfileID: snapshot.profileID, ProfileToken: snapshot.profileToken, SessionID: snapshot.session, Request: request, SourceSHA256: identity.source, ConfigSHA256: identity.config, NetworkSHA256: desktopResponseNetworkDigest(identity.network), Measurement: "routed-https-response-after-tls"})
}
