package main

import (
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
)

type desktopNodeCandidatePrefixRequest struct {
	Schema     int                                                       `json:"schema"`
	Request    string                                                    `json:"request_id"`
	Generation uint64                                                    `json:"generation"`
	Deadline   int64                                                     `json:"deadline_at"`
	Position   int                                                       `json:"prefix_position"`
	Candidate  string                                                    `json:"candidate_id"`
	CaptureSHA string                                                    `json:"capture_sha256"`
	Path       string                                                    `json:"path_id"`
	Capture    mobilemultihop.DesktopNodeCandidatePreparationReadyRecord `json:"capture"`
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
	CompletedAt int64                      `json:"completed_at"`
	Status      hopmeasure.CandidateStatus `json:"status"`
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
	if json.Unmarshal([]byte(preparation.prefixPreparation.Metadata()), &metadata) != nil {
		return empty, errors.New("candidate plan lost its sealed metadata")
	}
	deadline, _ := ctx.Deadline()
	request := desktopNodeCandidatePrefixRequest{Schema: 1, Request: nonce, Generation: chain.candidateGeneration + 1,
		Deadline: deadline.UnixMilli(), Position: metadata.PrefixPosition, Candidate: id, CaptureSHA: preparation.prefixPreparation.CaptureSHA256(),
		Path: live.Path, Capture: capture}
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
		if decodeRelayControlJSON(raw, &result) != nil {
			return nil, errors.New("candidate result is malformed")
		}
		if result.Request != request.Request {
			if result.Request == chain.candidateLast {
				return nil, nil
			}
			return nil, errors.New("candidate result belongs to a different request")
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
				return empty, errors.New("candidate timing failed, changed, or expired")
			}
			if err := check(ctx); err != nil {
				return empty, err
			}
			if err := current(ctx); err != nil {
				return empty, err
			}
			if err := validateDesktopNodeCandidatePrefixStatus(preparation.prefixPreparation, id, result.Status, time.Now()); err != nil {
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
	bad := errors.New("candidate result did not retain its exact fifty-sample original prefix and source")
	if plan == nil {
		return bad
	}
	var metadata struct {
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
	if source == "" || status.Schema != 1 || status.Measurement != "routed-tcp-connect" || status.PrefixPosition != metadata.PrefixPosition ||
		status.PrefixID != metadata.PrefixID || status.CaptureSHA256 != plan.CaptureSHA256() || status.CandidateID != id || status.CandidateSourceSHA256 != source ||
		status.Stage != "complete" || status.Failure != "" || !status.Complete || !status.Drained || len(status.Results) != 1 ||
		status.MeasuredAt <= 0 || status.MeasuredAt > now.UnixMilli() || status.ExpiresAt != status.MeasuredAt+hopmeasure.CandidateReceiptLifetime.Milliseconds() || status.ExpiresAt <= now.UnixMilli() {
		return bad
	}
	r := status.Results[0]
	if r.ID != id || r.Role != "candidate" || r.Kind != "tcp-connect" || !r.Ready || r.Failure != "" || r.Idle != nil || r.Response != nil || r.Download != nil || r.Upload != nil || r.Benchmark == nil {
		return bad
	}
	b := r.Benchmark
	if b.Schema != 1 || b.Measurement != "routed-tcp-connect" || b.Endpoint != "" || b.Attempts != hopmeasure.LatencyBenchmarkSamples || b.Failed != 0 || b.Distribution == nil {
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
