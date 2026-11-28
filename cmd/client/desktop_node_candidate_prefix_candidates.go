package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"math"
	"os"
	"reflect"
	"sync/atomic"
	"time"

	"router-vpn/internal/hopmeasure"
	"router-vpn/internal/mobilemtu"
	"router-vpn/internal/mobilemultihop"
	"router-vpn/internal/routechoice"
)

type desktopNodeCandidatePrefixRequest struct {
	Schema              int                                                            `json:"schema"`
	Request             string                                                         `json:"request_id"`
	Generation          uint64                                                         `json:"generation"`
	Deadline            int64                                                          `json:"deadline_at"`
	Position            int                                                            `json:"prefix_position"`
	Candidate           string                                                         `json:"candidate_id"`
	CaptureSHA          string                                                         `json:"capture_sha256"`
	Path                string                                                         `json:"path_id"`
	Capture             mobilemultihop.DesktopNodeCandidatePreparationReadyRecord      `json:"capture"`
	ExecutionCaptureSHA string                                                         `json:"execution_capture_sha256,omitempty"`
	ExecutionCapture    *mobilemultihop.DesktopNodeCandidateAppendExecutionReadyRecord `json:"execution_capture,omitempty"`
}

type desktopNodeCandidatePrefixPulse struct {
	Schema     int    `json:"schema"`
	Request    string `json:"request_id"`
	CaptureSHA string `json:"capture_sha256"`
	Sequence   uint64 `json:"sequence"`
	ObservedAt int64  `json:"observed_at"`
}

type desktopNodeCandidatePrefixResult struct {
	desktopNodeCandidatePrefixRequest
	CompletedAt     int64                      `json:"completed_at"`
	Status          hopmeasure.CandidateStatus `json:"status"`
	executionStatus json.RawMessage
}

// Only the dedicated execution command returns the enriched raw status. Its
// original request echo remains the existing Local prefix request plus the two
// separately retained discovery fields.
type desktopNodeCandidateAppendExecutionResult struct {
	desktopNodeCandidatePrefixRequest
	CompletedAt int64           `json:"completed_at"`
	Status      json.RawMessage `json:"status"`
}

type desktopNodeCandidateAppendExecutionStatus struct {
	hopmeasure.CandidateStatus
	Purpose                string          `json:"purpose"`
	SourceSHA256           string          `json:"source_sha256"`
	ExecutionSourceSHA256  string          `json:"execution_source_sha256"`
	ExecutionCaptureSHA256 string          `json:"execution_capture_sha256"`
	RequestedExecution     string          `json:"requested_execution"`
	WinningExecution       string          `json:"winning_execution"`
	Selection              json.RawMessage `json:"selection,omitempty"`
}

// The failure carries this exact original retirement handle. A later cleanup
// must never look up a different request using the current profile or mailbox.
type desktopNodeCandidatePrefixRetirement struct {
	launch  *desktopNodeLaunch
	request string
	run     func(context.Context) error // serialized by the original measurementMu
	joined  atomic.Bool
}

type desktopNodeCandidatePrefixPendingError struct {
	retirement *desktopNodeCandidatePrefixRetirement
	cause      error
}

func (e *desktopNodeCandidatePrefixPendingError) Error() string {
	return errors.Join(e.cause, errDesktopNodeChainMeasurementPending).Error()
}

func (e *desktopNodeCandidatePrefixPendingError) Unwrap() []error {
	return []error{e.cause, errDesktopNodeChainMeasurementPending}
}

func retryDesktopNodeCandidatePrefixDrain(ctx context.Context, launch *desktopNodeLaunch, failure error) error {
	var pending *desktopNodeCandidatePrefixPendingError
	if ctx == nil || !errors.As(failure, &pending) || pending == nil || pending.retirement == nil || launch == nil || launch.candidatePrefix == nil || pending.retirement.launch != launch {
		return errors.New("candidate cleanup requires its exact retained original failure")
	}
	retirement := pending.retirement
	if err := mobilemtu.LockContext(ctx, &launch.candidatePrefix.measurementMu); err != nil {
		return &desktopNodeCandidatePrefixPendingError{retirement, err}
	}
	defer launch.candidatePrefix.measurementMu.Unlock()
	if retirement.joined.Load() {
		return nil
	}
	if err := mobilemtu.LockContext(ctx, &launch.candidatePrefix.mu); err != nil {
		return &desktopNodeCandidatePrefixPendingError{retirement, err}
	}
	current := launch.candidatePrefix.candidatePending == retirement
	launch.candidatePrefix.mu.Unlock()
	if !current {
		return errors.New("candidate cleanup cannot retire a replacement owner")
	}
	if err := retirement.run(ctx); err != nil && !retirement.joined.Load() {
		return &desktopNodeCandidatePrefixPendingError{retirement, err}
	}
	if err := finishDesktopNodeCandidatePrefixRetirement(ctx, retirement); err != nil {
		return &desktopNodeCandidatePrefixPendingError{retirement, err}
	}
	return nil
}

// Called with measurementMu held. Workspace retirement can also mark this
// exact handle joined, only after the original child and directory are gone.
func finishDesktopNodeCandidatePrefixRetirement(ctx context.Context, retirement *desktopNodeCandidatePrefixRetirement) error {
	prefix := retirement.launch.candidatePrefix
	if err := mobilemtu.LockContext(ctx, &prefix.mu); err != nil {
		return err
	}
	defer prefix.mu.Unlock()
	if retirement.joined.Load() {
		return nil
	}
	if prefix.candidatePending != retirement {
		return errors.New("prefix completion cannot consume another pending owner")
	}
	prefix.candidatePending = nil
	prefix.candidateLast = retirement.request
	retirement.joined.Store(true)
	return ctx.Err()
}

// The distinct child retains its own prefix preparation, not an ordinary
// full-chain catalog. Saved source inventory is rechecked only as provenance.
func exchangeDesktopNodeCandidatePrefixObserved(parent context.Context, runtime *orderedCandidatePreparedRuntime, id string,
	current, pulseCurrent func(context.Context) error) (hopmeasure.CandidateStatus, error) {
	var empty hopmeasure.CandidateStatus
	if parent == nil || parent.Err() != nil || runtime == nil || runtime.preparation == nil ||
		runtime.preparation.prefixPreparation == nil || runtime.catalog == nil || runtime.catalog.profiles[id] == "" ||
		runtime.preparation.launch == nil || runtime.preparation.launch.candidatePrefix == nil || current == nil || pulseCurrent == nil {
		return empty, errors.New("prefix measurement requires its original closed native purpose")
	}
	preparation := runtime.preparation
	ctx, cancel := context.WithTimeout(parent, hopmeasure.RequestTimeout)
	defer cancel()
	launch, chain := preparation.launch, preparation.launch.candidatePrefix
	if err := mobilemtu.LockContext(ctx, &chain.measurementMu); err != nil {
		return empty, err
	}
	defer chain.measurementMu.Unlock()
	if err := mobilemtu.LockContext(ctx, &chain.mu); err != nil {
		return empty, err
	}
	pending := chain.candidatePending != nil
	chain.mu.Unlock()
	if pending {
		return empty, errDesktopNodeChainMeasurementPending
	}
	if err := current(ctx); err != nil {
		return empty, err
	}
	live, err := readDesktopNodeMTUContext(ctx, launch)
	if err != nil || live.Active || live.Failure != "" {
		return empty, errors.Join(err, errors.New("candidate timing lost its idle original MTU reader"))
	}
	if err := mobilemtu.LockContext(ctx, &chain.mu); err != nil {
		return empty, err
	}
	if chain.ready == nil {
		chain.mu.Unlock()
		return empty, errors.New("candidate timing has no proved original chain")
	}
	capture := *chain.ready
	chain.mu.Unlock()
	capture, err = readDesktopNodeCandidatePrefixReadyContext(ctx, launch, capture.TransferSHA256, time.UnixMilli(capture.ObservedAt), false, live)
	if err != nil {
		return empty, err
	}
	// The native request belongs to the retained desktop projection. The
	// unprojected source/capture remains separately bound by policy metadata.
	projected, err := desktopNodeCandidatePrefixProjectedPreparation(preparation)
	if err != nil {
		return empty, err
	}
	var executionCapture *mobilemultihop.DesktopNodeCandidateAppendExecutionReadyRecord
	if chain.executionPolicy != nil {
		if err := mobilemtu.LockContext(ctx, &chain.mu); err != nil {
			return empty, err
		}
		if chain.executionReady == nil {
			chain.mu.Unlock()
			return empty, errors.New("append timing has no authenticated original discovery")
		}
		retained := *chain.executionReady
		chain.mu.Unlock()
		if retained.Validate(chain.executionPolicy, capture.TransferSHA256, capture) != nil {
			return empty, errors.New("append timing changed its retained discovery")
		}
		executionCapture = &retained
	}
	if chain.candidateGeneration == ^uint64(0) {
		return empty, errors.New("candidate request generation exhausted")
	}
	nonce, err := randomHex(16)
	if err != nil {
		return empty, err
	}
	var metadata struct {
		PrefixPosition int `json:"prefix_position"`
	}
	if json.Unmarshal([]byte(projected.Metadata()), &metadata) != nil {
		return empty, errors.New("candidate plan lost its sealed metadata")
	}
	deadline, _ := ctx.Deadline()
	request := desktopNodeCandidatePrefixRequest{Schema: 1, Request: nonce, Generation: chain.candidateGeneration + 1,
		Deadline: deadline.UnixMilli(), Position: metadata.PrefixPosition, Candidate: id, CaptureSHA: projected.CaptureSHA256(),
		Path: live.Path, Capture: capture}
	if executionCapture != nil {
		request.ExecutionCaptureSHA, request.ExecutionCapture = executionCapture.ExecutionCaptureSHA256, executionCapture
	}
	raw, _ := json.Marshal(request)
	check := func(call context.Context) error {
		if err := pulseCurrent(call); err != nil {
			return err
		}
		after, err := readDesktopNodeMTUContext(call, launch)
		if err != nil {
			return err
		}
		if after.Session != live.Session || after.Config != live.Config || after.Path != live.Path || after.Reader != live.Reader ||
			after.Interface != live.Interface || after.Index != live.Index || after.MTU != live.MTU || after.Active || after.Failure != "" {
			return errors.New("candidate original TUN reader changed")
		}
		if chain.executionPolicy != nil {
			if _, err := readDesktopNodeCandidatePrefixReadyContext(call, launch, capture.TransferSHA256, time.UnixMilli(capture.ObservedAt), false, after); err != nil {
				return err
			}
			if err := mobilemtu.LockContext(call, &chain.mu); err != nil {
				return err
			}
			unchanged := chain.executionReady != nil && chain.executionReady.ExecutionCaptureSHA256 == request.ExecutionCaptureSHA && chain.executionPolicyCurrent()
			chain.mu.Unlock()
			if !unchanged {
				return errors.New("append timing changed its original runtime discovery")
			}
		}
		return call.Err()
	}
	var pulseInfo os.FileInfo
	var pulseSequence uint64
	cleanup := func(call context.Context) error {
		return retireDesktopNodeCandidatePrefixFile(call, launch, "node-candidate-prefix-live.json", pulseInfo)
	}
	pulse := func(call context.Context) error {
		if err := check(call); err != nil {
			return err
		}
		pulseSequence++
		value := desktopNodeCandidatePrefixPulse{Schema: 1, Request: request.Request, CaptureSHA: request.CaptureSHA,
			Sequence: pulseSequence, ObservedAt: time.Now().UnixMilli()}
		var err error
		pulseInfo, err = publishDesktopNodeCandidatePrefixPulse(call, launch, value, pulseInfo)
		return err
	}
	var started int64
	var requestInfo os.FileInfo
	exposed := false
	read := func(call context.Context) (*desktopNodeCandidatePrefixResult, error) {
		raw, err := readDesktopRuntimeFileContext(call, launch, "node-candidate-prefix-result.json", 128<<10)
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		var result desktopNodeCandidatePrefixResult
		if chain.executionPolicy != nil {
			var wire desktopNodeCandidateAppendExecutionResult
			if decodeRelayControlJSON(raw, &wire) != nil {
				return nil, errors.New("append execution result is malformed")
			}
			result.desktopNodeCandidatePrefixRequest, result.CompletedAt = wire.desktopNodeCandidatePrefixRequest, wire.CompletedAt
			result.executionStatus = append(json.RawMessage(nil), wire.Status...)
		} else if decodeRelayControlJSON(raw, &result) != nil {
			return nil, errors.New("candidate result is malformed")
		}
		if result.Request != request.Request {
			if result.Request == chain.candidateLast {
				return nil, nil
			}
			return nil, errors.New("candidate result belongs to a different request")
		}
		if chain.executionPolicy != nil {
			decoded, err := decodeDesktopNodeCandidateAppendExecutionStatus(chain, request, result.executionStatus)
			if err != nil {
				return nil, err
			}
			result.Status = decoded.CandidateStatus
		}
		if !reflect.DeepEqual(result.desktopNodeCandidatePrefixRequest, request) || result.CompletedAt < started-1 || result.CompletedAt > time.Now().Add(time.Second).UnixMilli() ||
			result.Status.Request != request.Request || !result.Status.Complete || !result.Status.Drained {
			return nil, errors.New("candidate result changed the original capture or did not drain")
		}
		if _, err := readDesktopRuntimeFileContext(call, launch, "node-candidate-prefix-request.json", 16384); !errors.Is(err, os.ErrNotExist) {
			if err != nil {
				return nil, err
			}
			return nil, nil
		}
		return &result, nil
	}
	var cancelInfo os.FileInfo
	retirement := &desktopNodeCandidatePrefixRetirement{launch: launch, request: request.Request}
	retireFiles := func(call context.Context, stopped bool) error {
		var requestErr error
		if stopped {
			requestErr = retireDesktopNodeCandidatePrefixFile(call, launch, "node-candidate-prefix-request.json", requestInfo)
		}
		return errors.Join(requestErr, retireDesktopNodeCandidatePrefixCancel(call, launch, raw, cancelInfo), cleanup(call))
	}
	retirement.run = func(call context.Context) error {
		if !exposed {
			return cleanup(call)
		}
		if result, err := read(call); err == nil && result != nil {
			return retireFiles(call, false)
		}
		if stopped, _ := readDesktopNodeStoppedContext(call, launch); stopped {
			return retireFiles(call, true)
		}
		// A retry observes only the cancel inode captured by this original
		// producer. The native consumer may already have removed it.
		if err := mobilemtu.LockContext(call, &launch.workspaceMu); err != nil {
			return err
		}
		info, statErr := launch.directoryRoot.Lstat("node-candidate-prefix-cancel.json")
		valid := statErr == nil && cancelInfo != nil && os.SameFile(cancelInfo, info)
		launch.workspaceMu.Unlock()
		if errors.Is(statErr, os.ErrNotExist) {
			if err := publishDesktopNodeChainMeasurement(call, launch, "node-candidate-prefix-cancel.json", raw); err != nil {
				return err
			}
			cancelInfo, statErr = launch.directoryRoot.Lstat("node-candidate-prefix-cancel.json")
			if statErr != nil && !errors.Is(statErr, os.ErrNotExist) {
				return statErr
			}
		} else if !valid {
			return errors.New("candidate cleanup cannot replace another cancellation inode")
		}
		poll := time.NewTicker(100 * time.Millisecond)
		defer poll.Stop()
		for {
			if result, err := read(call); err == nil && result != nil {
				return retireFiles(call, false)
			}
			if stopped, _ := readDesktopNodeStoppedContext(call, launch); stopped {
				return retireFiles(call, true)
			}
			select {
			case <-call.Done():
				return call.Err()
			case <-poll.C:
			}
		}
	}
	// Reserve cleanup before exposing any native request. If finalization is
	// interrupted, this exact handle remains reachable for a bounded retry.
	if err := mobilemtu.LockContext(ctx, &chain.mu); err != nil {
		return empty, err
	}
	chain.candidatePending = retirement
	chain.mu.Unlock()
	drain := func(cause error) (hopmeasure.CandidateStatus, error) {
		budget := 7 * time.Second
		if !exposed {
			budget = 2 * time.Second
		}
		joined, stop := context.WithTimeout(context.Background(), budget)
		defer stop()
		if err := retirement.run(joined); err != nil && !retirement.joined.Load() {
			return empty, &desktopNodeCandidatePrefixPendingError{retirement, errors.Join(cause, err)}
		}
		if err := finishDesktopNodeCandidatePrefixRetirement(joined, retirement); err != nil {
			return empty, &desktopNodeCandidatePrefixPendingError{retirement, errors.Join(cause, err)}
		}
		return empty, cause
	}
	if err := pulse(ctx); err != nil {
		return drain(err)
	}
	started = time.Now().UnixMilli()
	if err := publishDesktopNodeChainMeasurement(ctx, launch, "node-candidate-prefix-request.json", raw); err != nil {
		return drain(err)
	}
	exposed = true
	chain.candidateGeneration = request.Generation
	requestInfo, _ = launch.directoryRoot.Lstat("node-candidate-prefix-request.json")
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		if err := pulse(ctx); err != nil {
			return drain(errors.Join(err, ctx.Err()))
		}
		result, err := read(ctx)
		if err != nil {
			return drain(errors.Join(err, ctx.Err()))
		}
		if result != nil {
			if err := retireFiles(ctx, false); err != nil {
				return drain(err)
			}
			if err := finishDesktopNodeCandidatePrefixRetirement(ctx, retirement); err != nil {
				return empty, &desktopNodeCandidatePrefixPendingError{retirement, err}
			}
			if result.CompletedAt > request.Deadline || result.Status.Failure != "" {
				failure := errors.New("candidate timing failed, changed, or expired")
				if chain.executionPolicy != nil {
					return result.Status, failure
				}
				return empty, failure
			}
			if err := check(ctx); err != nil {
				return empty, err
			}
			if err := current(ctx); err != nil {
				return empty, err
			}
			if chain.executionPolicy != nil {
				if err := validateDesktopNodeCandidateAppendExecutionStatus(chain, request, result.executionStatus, time.Now()); err != nil {
					return result.Status, err
				}
				if err := preparation.retainAppendExecutionResult(id, result.Status, result.executionStatus); err != nil {
					return result.Status, err
				}
			} else if err := validateDesktopNodeCandidatePrefixStatus(projected, id, result.Status, time.Now()); err != nil {
				return empty, err
			}
			return result.Status, nil
		}
		select {
		case <-ctx.Done():
			return drain(ctx.Err())
		case <-ticker.C:
		}
	}
}

func validateDesktopNodeCandidatePrefixStatus(plan *mobilemultihop.NodeChainCandidatePreparation, id string, status hopmeasure.CandidateStatus, now time.Time) error {
	capture := ""
	if plan != nil {
		capture = plan.CaptureSHA256()
	}
	return validateDesktopNodeCandidatePrefixStatusCapture(plan, id, status, now, capture)
}

func validateDesktopNodeCandidatePrefixStatusCapture(plan *mobilemultihop.NodeChainCandidatePreparation, id string, status hopmeasure.CandidateStatus, now time.Time, capture string) error {
	bad := errors.New("candidate result did not retain its exact fifty-sample original prefix and source")
	if plan == nil || capture == "" {
		return bad
	}
	var metadata struct {
		Measurement    string `json:"measurement"`
		PrefixPosition int    `json:"prefix_position"`
		PrefixID       string `json:"prefix_id"`
		Targets        []struct {
			ID     string `json:"id"`
			Source string `json:"source_sha256"`
		} `json:"targets"`
	}
	if json.Unmarshal([]byte(plan.Metadata()), &metadata) != nil {
		return bad
	}
	source := ""
	for _, target := range metadata.Targets {
		if target.ID == id {
			source = target.Source
		}
	}
	metric, kind, endpoint := hopmeasure.CandidateTCPMeasurement, "tcp-connect", ""
	switch metadata.Measurement {
	case "":
	case hopmeasure.CandidatePrivateResponseMeasurement:
		metric, kind = metadata.Measurement, "private-agent-response"
	case hopmeasure.CandidatePublicResponseMeasurement:
		metric, kind, endpoint = metadata.Measurement, "public-exit-response", hopmeasure.CandidatePublicResponseEndpoint
	default:
		return bad
	}
	if source == "" || status.Schema != 1 || status.Measurement != metric || status.PrefixPosition != metadata.PrefixPosition ||
		status.PrefixID != metadata.PrefixID || status.CaptureSHA256 != capture || status.CandidateID != id || status.CandidateSourceSHA256 != source ||
		status.Stage != "complete" || status.Failure != "" || !status.Complete || !status.Drained || len(status.Results) != 1 ||
		status.MeasuredAt <= 0 || status.MeasuredAt > now.UnixMilli() || status.ExpiresAt != status.MeasuredAt+hopmeasure.CandidateReceiptLifetime.Milliseconds() || status.ExpiresAt <= now.UnixMilli() {
		return bad
	}
	r := status.Results[0]
	if r.ID != id || r.Role != "candidate" || r.Kind != kind || !r.Ready || r.Failure != "" || r.CandidateDisposition != "" || r.Idle != nil || r.Response != nil || r.Download != nil || r.Upload != nil || r.Benchmark == nil {
		return bad
	}
	b := r.Benchmark
	if b.Schema != 1 || b.Measurement != metric || b.Endpoint != endpoint || b.Attempts != hopmeasure.LatencyBenchmarkSamples || b.Failed != 0 || b.Distribution == nil {
		return bad
	}
	d := b.Distribution
	finite := func(v float64) bool { return !math.IsNaN(v) && !math.IsInf(v, 0) && v > 0 }
	if d.Samples != hopmeasure.LatencyBenchmarkSamples || !finite(d.Min) || !finite(d.Median) || !finite(d.Average) || !finite(d.P90) || !finite(d.Max) || !finite(b.TrimmedMean) ||
		math.IsNaN(d.Jitter) || math.IsInf(d.Jitter, 0) || d.Jitter < 0 || d.Min > d.Median || d.Median > d.P90 || d.P90 > d.Max || d.Average < d.Min || d.Average > d.Max || b.TrimmedMean < d.Min || b.TrimmedMean > d.Max {
		return bad
	}
	return nil
}

// This is only a retained source/projection check. It does not grant readiness
// after native DOWN, and it never reconstructs a plan from the current store.
func desktopNodeCandidatePrefixProjectedPreparation(p *orderedCandidatePreparation) (*mobilemultihop.NodeChainCandidatePreparation, error) {
	bad := errors.New("candidate receipt lost its original desktop projection")
	if p == nil || p.prefixPreparation == nil || p.launch == nil || p.launch.candidatePrefix == nil {
		return nil, bad
	}
	owner := p.launch.candidatePrefix
	if owner.preparation != p || owner.policy == nil || owner.policy.Validate() != nil || !owner.executionPolicyCurrent() || owner.selection.Native != p.selection.Native {
		return nil, bad
	}
	meta := owner.policy.Metadata()
	projected := owner.policy.Preparation()
	if projected == nil || meta.PreparationSHA256 != p.prefixPreparation.SourceSHA256() || meta.OriginalCaptureSHA256 != p.prefixPreparation.CaptureSHA256() ||
		meta.SourceSHA256 != projected.SourceSHA256() || meta.ConfigSHA256 != projected.ConfigSHA256() || meta.CaptureSHA256 != projected.CaptureSHA256() || meta.PrefixPosition != p.request.Position {
		return nil, bad
	}
	return projected, nil
}

func validateDesktopNodeCandidatePrefixStatusForPreparation(p *orderedCandidatePreparation, id string, status hopmeasure.CandidateStatus, now time.Time) error {
	if p == nil || p.appendExecutionPreparation != nil {
		return errors.New("Local candidate receipt has another execution purpose")
	}
	projected, err := desktopNodeCandidatePrefixProjectedPreparation(p)
	if err != nil {
		return err
	}
	return validateDesktopNodeCandidatePrefixStatus(projected, id, status, now)
}

// The typed decoder rejects unknown/duplicate fields. This presence check also
// rejects null or omitted mandatory members whose Go zero value is meaningful.
func desktopNodeCandidateExecutionFields(raw []byte, required ...string) (map[string]json.RawMessage, bool) {
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || fields == nil {
		return nil, false
	}
	for _, value := range fields {
		if len(value) == 0 || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return nil, false
		}
	}
	for _, key := range required {
		if _, exists := fields[key]; !exists {
			return nil, false
		}
	}
	return fields, true
}

func decodeDesktopNodeCandidateAppendExecutionStatus(owner *desktopNodeCandidatePrefixLaunch, request desktopNodeCandidatePrefixRequest, raw json.RawMessage) (desktopNodeCandidateAppendExecutionStatus, error) {
	var status desktopNodeCandidateAppendExecutionStatus
	bad := errors.New("append execution status changed its original request, source or discovery")
	if owner == nil || owner.executionPolicy == nil || !owner.executionPolicyCurrent() || request.ExecutionCapture == nil || !desktopNodeProcessHex(request.ExecutionCaptureSHA, 32) ||
		request.ExecutionCapture.ExecutionCaptureSHA256 != request.ExecutionCaptureSHA || request.ExecutionCapture.Validate(owner.executionPolicy, request.Capture.TransferSHA256, request.Capture) != nil {
		return status, bad
	}
	projected := owner.policy.Preparation()
	execution := owner.executionPolicy.ExecutionPreparation()
	if projected == nil || execution == nil || execution.OriginalPreparation() != projected || request.CaptureSHA != projected.CaptureSHA256() {
		return status, bad
	}
	var metadata struct {
		PrefixPosition int    `json:"prefix_position"`
		PrefixID       string `json:"prefix_id"`
		Targets        []struct {
			ID     string `json:"id"`
			Source string `json:"source_sha256"`
		} `json:"targets"`
	}
	if json.Unmarshal([]byte(projected.Metadata()), &metadata) != nil || metadata.PrefixID == "" {
		return status, bad
	}
	targetSource := ""
	for _, target := range metadata.Targets {
		if target.ID == request.Candidate {
			if targetSource != "" {
				return status, bad
			}
			targetSource = target.Source
		}
	}
	if !desktopNodeProcessHex(targetSource, 32) || decodePrivateControlJSONBounded(raw, &status, 128<<10) != nil {
		return status, bad
	}
	if _, ok := desktopNodeCandidateExecutionFields(raw, "request_id", "stage", "complete", "drained", "results", "schema", "measurement", "prefix_position", "prefix_id", "capture_sha256", "purpose", "source_sha256", "execution_source_sha256", "execution_capture_sha256", "requested_execution", "winning_execution"); !ok {
		return status, bad
	}
	if status.Request != request.Request || status.Stage == "" || status.Schema != 1 || status.Measurement != hopmeasure.CandidatePrivateResponseMeasurement ||
		status.PrefixPosition != request.Position || status.PrefixPosition != metadata.PrefixPosition || status.PrefixID != metadata.PrefixID || status.CaptureSHA256 != request.ExecutionCaptureSHA ||
		status.Purpose != "draft-prefix-append-execution" || status.SourceSHA256 != execution.OriginalSourceSHA256() || status.ExecutionSourceSHA256 != execution.SourceSHA256() ||
		status.ExecutionCaptureSHA256 != request.ExecutionCaptureSHA || status.RequestedExecution != execution.Execution() ||
		status.RequestedExecution != "server" && status.RequestedExecution != "auto" || status.Results == nil ||
		status.CandidateID != "" && status.CandidateID != request.Candidate || status.CandidateSourceSHA256 != "" && status.CandidateSourceSHA256 != targetSource ||
		status.MeasuredAt < 0 || status.ExpiresAt < 0 || (status.MeasuredAt == 0) != (status.ExpiresAt == 0) ||
		status.WinningExecution != "" && status.WinningExecution != "local" && status.WinningExecution != "server" ||
		status.RequestedExecution == "server" && (status.WinningExecution != "" && status.WinningExecution != "server" || len(status.Selection) != 0) {
		return status, bad
	}
	if len(status.Selection) != 0 {
		prefixes := owner.policy.Metadata().Prefixes
		if status.RequestedExecution != "auto" || len(prefixes) == 0 || validateDesktopNodeCandidateAppendExecutionSelection(status.Selection, prefixes[0].ProfileID, request.Candidate, status.WinningExecution, false) != nil {
			return status, bad
		}
	}
	return status, nil
}

func validateDesktopNodeCandidateAppendExecutionStatus(owner *desktopNodeCandidatePrefixLaunch, request desktopNodeCandidatePrefixRequest, raw json.RawMessage, now time.Time) error {
	status, err := decodeDesktopNodeCandidateAppendExecutionStatus(owner, request, raw)
	if err != nil {
		return err
	}
	if err := validateDesktopNodeCandidatePrefixStatusCapture(owner.policy.Preparation(), request.Candidate, status.CandidateStatus, now, request.ExecutionCaptureSHA); err != nil {
		return err
	}
	if status.RequestedExecution == "server" {
		if status.WinningExecution != "server" || len(status.Selection) != 0 {
			return errors.New("Server candidate result changed its actual lane")
		}
		return nil
	}
	prefixes := owner.policy.Metadata().Prefixes
	if len(prefixes) == 0 || status.WinningExecution == "" || len(status.Selection) == 0 {
		return errors.New("Compare candidate has no original final selection")
	}
	return validateDesktopNodeCandidateAppendExecutionSelection(status.Selection, prefixes[0].ProfileID, request.Candidate, status.WinningExecution, true)
}

func validateDesktopNodeCandidateAppendExecutionSelection(raw json.RawMessage, entry, candidate, winning string, complete bool) error {
	bad := errors.New("append Compare result changed its original two routed trials or final recheck")
	var selection routechoice.Result
	if entry == "" || candidate == "" || entry == candidate || decodePrivateControlJSONBounded(raw, &selection, 128<<10) != nil {
		return bad
	}
	fields, ok := desktopNodeCandidateExecutionFields(raw, "target", "measurements")
	if !ok || selection.Target != "https://1.1.1.1/cdn-cgi/trace" && selection.Target != "https://1.0.0.1/cdn-cgi/trace" || len(selection.Measurements) > 2 {
		return bad
	}
	validCandidate := func(value routechoice.Candidate) bool {
		return value.Valid() && value.Transport == "ordered-prefix-append" && value.EntryID == entry && value.ExitID == candidate
	}
	finite := func(value float64) bool { return !math.IsNaN(value) && !math.IsInf(value, 0) && value >= 0 }
	validMeasurement := func(value routechoice.Measurement, original json.RawMessage) bool {
		if _, ok := desktopNodeCandidateExecutionFields(original, "candidate", "eligible"); !ok {
			return false
		}
		if !validCandidate(value.Candidate) || !finite(value.LastNodeMS) || !finite(value.ExternalMS) {
			return false
		}
		if !value.Eligible {
			return value.Failure != "" && value.ScoreMS == nil
		}
		if value.Failure != "" || value.LastNodeMS <= 0 || value.ExternalMS <= 0 || value.ScoreMS == nil || !finite(*value.ScoreMS) || *value.ScoreMS <= 0 {
			return false
		}
		expected := value.LastNodeMS/2 + value.ExternalMS/2
		return math.Abs(*value.ScoreMS-expected) <= math.Max(1, expected)*1e-9
	}
	var originals []json.RawMessage
	if json.Unmarshal(fields["measurements"], &originals) != nil || len(originals) != len(selection.Measurements) {
		return bad
	}
	seen := map[routechoice.Execution]bool{}
	best, selected := math.Inf(1), math.Inf(1)
	for i, trial := range selection.Measurements {
		if seen[trial.Candidate.Execution] || !validMeasurement(trial, originals[i]) {
			return bad
		}
		seen[trial.Candidate.Execution] = true
		if trial.Eligible {
			if *trial.ScoreMS < best {
				best = *trial.ScoreMS
			}
			if selection.Winner != nil && trial.Candidate == *selection.Winner {
				selected = *trial.ScoreMS
			}
		}
	}
	if selection.Winner != nil && (!validCandidate(*selection.Winner) || math.IsInf(selected, 1) || selected > best+math.Max(1, best)*1e-9) {
		return bad
	}
	if selection.Final != nil && (selection.Winner == nil || selection.Final.Candidate != *selection.Winner || !validMeasurement(*selection.Final, fields["final"])) {
		return bad
	}
	if complete && (len(selection.Measurements) != 2 || !seen[routechoice.Local] || !seen[routechoice.Server] || selection.Winner == nil || string(selection.Winner.Execution) != winning || selection.Final == nil || !selection.Final.Eligible) {
		return bad
	}
	return nil
}

func publishDesktopNodeCandidatePrefixPulse(ctx context.Context, launch *desktopNodeLaunch, value desktopNodeCandidatePrefixPulse, previous os.FileInfo) (os.FileInfo, error) {
	const name = "node-candidate-prefix-live.json"
	raw, err := json.Marshal(value)
	if err != nil {
		return previous, err
	}
	if previous == nil {
		if err := publishDesktopNodeChainMeasurement(ctx, launch, name, raw); err != nil {
			return nil, err
		}
		return launch.directoryRoot.Lstat(name)
	}
	if err := mobilemtu.LockContext(ctx, &launch.workspaceMu); err != nil {
		return previous, err
	}
	defer launch.workspaceMu.Unlock()
	if err := desktopExternalDirectoryCurrent(launch); err != nil {
		return previous, err
	}
	actual, err := launch.directoryRoot.Lstat(name)
	if err != nil || !os.SameFile(previous, actual) {
		return previous, errors.New("candidate catalog pulse was replaced")
	}
	temporary := "." + name + ".pending"
	file, err := launch.directoryRoot.OpenFile(temporary, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return previous, err
	}
	info, statErr := file.Stat()
	defer func() {
		_ = file.Close()
		if actual, err := launch.directoryRoot.Lstat(temporary); err == nil && info != nil && os.SameFile(info, actual) {
			_ = launch.directoryRoot.Remove(temporary)
		}
	}()
	if statErr != nil {
		return previous, statErr
	}
	if _, err := file.Write(raw); err != nil {
		return previous, err
	}
	if err := file.Sync(); err != nil {
		return previous, err
	}
	if err := file.Close(); err != nil {
		return previous, err
	}
	actual, err = launch.directoryRoot.Lstat(name)
	if err != nil || !os.SameFile(previous, actual) || ctx.Err() != nil {
		return previous, errors.New("candidate catalog pulse lost its original owner")
	}
	if err := launch.directoryRoot.Rename(temporary, name); err != nil {
		return previous, err
	}
	actual, err = launch.directoryRoot.Lstat(name)
	if err != nil || !os.SameFile(info, actual) {
		return previous, errors.New("candidate catalog pulse changed during publication")
	}
	return actual, nil
}

func retireDesktopNodeCandidatePrefixFile(ctx context.Context, launch *desktopNodeLaunch, name string, info os.FileInfo) error {
	if info == nil {
		return nil
	}
	if name != "node-candidate-prefix-live.json" && name != "node-candidate-prefix-request.json" {
		return errors.New("invalid candidate cleanup source")
	}
	if err := mobilemtu.LockContext(ctx, &launch.workspaceMu); err != nil {
		return err
	}
	defer launch.workspaceMu.Unlock()
	if err := desktopExternalDirectoryCurrent(launch); err != nil {
		return err
	}
	actual, err := launch.directoryRoot.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || !os.SameFile(info, actual) {
		return errors.New("candidate cleanup source changed")
	}
	return launch.directoryRoot.Remove(name)
}

func retireDesktopNodeCandidatePrefixCancel(ctx context.Context, launch *desktopNodeLaunch, expected []byte, captured os.FileInfo) error {
	if err := mobilemtu.LockContext(ctx, &launch.workspaceMu); err != nil {
		return err
	}
	defer launch.workspaceMu.Unlock()
	if err := desktopExternalDirectoryCurrent(launch); err != nil {
		return err
	}
	const name = "node-candidate-prefix-cancel.json"
	before, err := launch.directoryRoot.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	actual, readErr := readDesktopRuntimeSnapshot(launch.directoryRoot, name, 16384)
	after, statErr := launch.directoryRoot.Lstat(name)
	if err != nil || readErr != nil || statErr != nil || captured == nil || !os.SameFile(captured, before) || !os.SameFile(before, after) || string(actual) != string(expected) {
		return errors.New("candidate cancellation changed before drain")
	}
	return launch.directoryRoot.Remove(name)
}
