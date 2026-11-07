package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"math"
	"os"
	"strconv"
	"strings"
	"time"

	"router-vpn/internal/hopmeasure"
)

type desktopLatencyNativeRequest struct {
	Schema       int    `json:"schema"`
	Session      string `json:"session_id"`
	SourceSHA256 string `json:"source_sha256"`
	ConfigSHA256 string `json:"config_sha256"`
	Generation   uint64 `json:"generation"`
	Request      string `json:"request_id"`
	NodeID       string `json:"node_id"`
}

type desktopLatencyNativeRecord struct {
	desktopLatencyNativeRequest
	Status hopmeasure.Status `json:"status"`
}

func decodeDesktopLatencyRecord(launch *desktopNodeLaunch, raw []byte) (desktopLatencyNativeRecord, error) {
	var record desktopLatencyNativeRecord
	bad := errors.New("native Latency result differs from the captured session, graph or request")
	owner, ownerErr := capturedDesktopLatencyRuntime(launch)
	if ownerErr != nil || len(raw) == 0 || len(raw) > 64<<10 || decodeRelayControlJSON(raw, &record) != nil {
		return record, bad
	}
	status := record.Status
	if record.Schema != 1 || record.Session != owner.session || record.SourceSHA256 != owner.source || record.ConfigSHA256 != owner.config || record.NodeID != owner.node || len(status.Results) > 1 || len(status.Failure) > 256 {
		return record, bad
	}
	if record.Generation == 0 {
		if record.Request != "" || status.Request != "" || status.Stage != "idle" || !status.Complete || !status.Drained || status.Failure != "" || len(status.Results) != 0 {
			return record, bad
		}
		return record, nil
	}
	if !desktopMTURequestPattern.MatchString(record.Request) || status.Request != record.Request || status.Drained && !status.Complete {
		return record, bad
	}
	if status.Stage == "starting" || desktopLatencyNativePhase(status.Stage) {
		if status.Complete || status.Drained || status.Failure != "" || len(status.Results) != 0 {
			return record, bad
		}
	} else {
		switch status.Stage {
		case "complete":
			if !status.Complete || status.Failure != "" || len(status.Results) != 1 {
				return record, bad
			}
		case "cancelled", "invalidated", "failed":
			if !status.Complete || status.Failure == "" || len(status.Results) != 0 {
				return record, bad
			}
		default:
			return record, bad
		}
	}
	return record, nil
}

func readDesktopLatencyRecord(launch *desktopNodeLaunch) (desktopLatencyNativeRecord, error) {
	return readDesktopLatencyRecordContext(context.Background(), launch)
}

func readDesktopLatencyRecordContext(ctx context.Context, launch *desktopNodeLaunch) (desktopLatencyNativeRecord, error) {
	raw, err := readDesktopRuntimeFileContext(ctx, launch, "latency-status.json", 64<<10)
	if err != nil {
		return desktopLatencyNativeRecord{}, err
	}
	return decodeDesktopLatencyRecord(launch, raw)
}

// Cleanup alone may follow the old captured directory handle after a rename.
// Result adoption always uses readDesktopLatencyRecord's strict pathname check.
func readDesktopLatencyDrainRecord(launch *desktopNodeLaunch) (desktopLatencyNativeRecord, error) {
	launch.workspaceMu.Lock()
	defer launch.workspaceMu.Unlock()
	if launch.directoryRoot == nil || launch.directoryInfo == nil {
		return desktopLatencyNativeRecord{}, errors.New("Latency cleanup lost its private directory owner")
	}
	current, err := launch.directoryRoot.Stat(".")
	if err != nil || !os.SameFile(current, launch.directoryInfo) {
		return desktopLatencyNativeRecord{}, errors.New("Latency cleanup directory belongs to another owner")
	}
	raw, err := readDesktopRuntimeSnapshot(launch.directoryRoot, "latency-status.json", 64<<10)
	if err != nil {
		return desktopLatencyNativeRecord{}, err
	}
	return decodeDesktopLatencyRecord(launch, raw)
}

func writeDesktopLatencyRequest(launch *desktopNodeLaunch, name string, request desktopLatencyNativeRequest) error {
	return writeDesktopLatencyRequestContext(context.Background(), launch, name, request)
}

func writeDesktopLatencyRequestContext(ctx context.Context, launch *desktopNodeLaunch, name string, request desktopLatencyNativeRequest) error {
	if name != "latency-request.json" && name != "latency-cancel.json" {
		return errors.New("invalid native Latency command")
	}
	raw, err := json.Marshal(request)
	if err != nil {
		return err
	}
	writeErr := writeDesktopRuntimeFileContext(ctx, launch, name, raw, true)
	if writeErr == nil {
		return nil
	}
	// The native loop can retire a consumed input before the writer's final
	// file-identity read. Only this exact native receipt acknowledges that race.
	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		record, err := readDesktopLatencyRecordContext(ctx, launch)
		if err == nil && record.desktopLatencyNativeRequest == request && (name == "latency-request.json" || record.Status.Complete && record.Status.Drained && record.Status.Stage == "cancelled") {
			return nil
		}
		if desktopExternalDirectoryCurrent(launch) != nil {
			return writeErr
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return writeErr
		case <-tick.C:
		}
	}
}

// Cancellation is cleanup of an already captured generation. It may follow
// the original directory handle after a rename; it never resolves the old
// pathname again or writes Start, policy, or connection commands this way.
func writeDesktopLatencyCleanupCancel(launch *desktopNodeLaunch, request desktopLatencyNativeRequest) error {
	owner, ownerErr := capturedDesktopLatencyRuntime(launch)
	if ownerErr != nil {
		return ownerErr
	}
	if request.Schema != 1 || request.Session != owner.session || request.SourceSHA256 != owner.source || request.ConfigSHA256 != owner.config || request.Generation == 0 || !desktopMTURequestPattern.MatchString(request.Request) {
		return errors.New("Latency cleanup command belongs to another owner")
	}
	raw, err := json.Marshal(request)
	if err != nil {
		return err
	}
	launch.workspaceMu.Lock()
	defer launch.workspaceMu.Unlock()
	if launch.directoryRoot == nil || launch.directoryInfo == nil {
		return errors.New("Latency cleanup lost its original directory handle")
	}
	root := launch.directoryRoot
	current, err := root.Stat(".")
	if err != nil || !os.SameFile(current, launch.directoryInfo) {
		return errors.New("Latency cleanup directory identity changed")
	}
	file, err := root.OpenFile("latency-cancel.json", os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			existing, readErr := readDesktopRuntimeSnapshot(root, "latency-cancel.json", 2048)
			if readErr == nil && bytes.Equal(existing, raw) {
				return nil
			}
		}
		return errors.New("Latency cleanup input already has another owner")
	}
	info, err := file.Stat()
	written := 0
	if err == nil {
		written, err = file.Write(raw)
	}
	if err == nil {
		err = file.Sync()
	}
	closed := file.Close()
	if err != nil || closed != nil {
		// Only our own incomplete, unparseable write may be removed for retry.
		// A complete control may already have been consumed by the native loop.
		if written < len(raw) && info != nil {
			if current, statErr := root.Lstat("latency-cancel.json"); statErr == nil && os.SameFile(current, info) && current.Size() < int64(len(raw)) {
				_ = root.Remove("latency-cancel.json")
			}
		}
		return errors.New("captured Latency cleanup publication is pending")
	}
	return nil // Only the later matching native receipt acknowledges drain.
}

func desktopLatencyNativePhase(stage string) bool {
	const prefix = "exit: HTTPS response "
	if !strings.HasPrefix(stage, prefix) || !strings.HasSuffix(stage, "/50") {
		return false
	}
	number := strings.TrimSuffix(strings.TrimPrefix(stage, prefix), "/50")
	value, err := strconv.Atoi(number)
	return err == nil && value >= 1 && value <= hopmeasure.LatencyBenchmarkSamples && strconv.Itoa(value) == number
}

func validateDesktopLatencyResults(launch *desktopNodeLaunch, status hopmeasure.Status) error {
	bad := errors.New("native latency has no complete, drained 50-response benchmark for this captured exit")
	owner, err := capturedDesktopLatencyRuntime(launch)
	if err != nil || !status.Complete || !status.Drained || status.Stage != "complete" || status.Failure != "" || len(status.Results) != 1 {
		return bad
	}
	result := status.Results[0]
	benchmark := result.Benchmark
	if !result.Ready || result.Failure != "" || result.ID != owner.node || result.Role != "exit" || result.Kind != "public-path" || result.Label != "External exit → Cloudflare edge" || result.Idle != nil || result.Download != nil || result.Upload != nil || benchmark == nil {
		return bad
	}
	if benchmark.Schema != 1 || benchmark.Measurement != "routed-https-response-after-tls" || benchmark.Endpoint != "https://"+hopmeasure.PublicHost+"/__down?bytes=1" || benchmark.Attempts != hopmeasure.LatencyBenchmarkSamples || benchmark.Failed != 0 || benchmark.Distribution == nil {
		return bad
	}
	d := benchmark.Distribution
	if d.Samples != hopmeasure.LatencyBenchmarkSamples {
		return bad
	}
	for _, value := range []float64{d.Min, d.Median, d.Average, d.P90, d.Max, benchmark.TrimmedMean} {
		if math.IsNaN(value) || math.IsInf(value, 0) || value <= 0 || value < d.Min || value > d.Max {
			return bad
		}
	}
	if d.Min > d.Median || d.Median > d.P90 || d.P90 > d.Max || math.IsNaN(d.Jitter) || math.IsInf(d.Jitter, 0) || d.Jitter < 0 || d.Jitter > d.Max-d.Min {
		return bad
	}
	return nil
}

// runDesktopLatencyNative owns the command generation and MTU hold until actual
// worker drain. Cancellation never closes a replacement VPN or releases a
// still-active measurement. A stubborn native close stays visibly draining.
func (a *app) runDesktopLatencyNative(ctx context.Context, operation *desktopLatencyOperation) (result hopmeasure.Status, failure error) {
	launch := operation.snapshot.launch
	owner, ownerErr := capturedDesktopLatencyRuntime(launch)
	if ownerErr != nil {
		return result, ownerErr
	}
	if !owner.lock.TryLock() {
		return result, errors.New("another native Latency measurement is still draining")
	}
	defer owner.lock.Unlock()
	if *owner.failed {
		return result, errors.New("native Latency control was retired; reconnect before Retest")
	}
	initial, err := readDesktopLatencyRecordContext(ctx, launch)
	if ctx.Err() != nil {
		return result, ctx.Err()
	}
	if err != nil || !initial.Status.Complete || !initial.Status.Drained || initial.Generation != *owner.generation || *owner.generation == ^uint64(0) {
		return result, errors.New("native Latency mailbox is unavailable or has another owner")
	}
	if err := operation.snapshot.currentContext(ctx, a); err != nil {
		return result, err
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	*owner.generation++
	request := desktopLatencyNativeRequest{Schema: 1, Session: owner.session, SourceSHA256: owner.source, ConfigSHA256: owner.config, Generation: *owner.generation, Request: operation.request, NodeID: owner.node}
	drained := false
	defer func() {
		if drained {
			return
		}
		operation.draining()
		tick := time.NewTicker(100 * time.Millisecond)
		defer tick.Stop()
		for {
			record, err := readDesktopLatencyDrainRecord(launch)
			acknowledged := err == nil && record.desktopLatencyNativeRequest == request && record.Status.Complete && record.Status.Drained
			if acknowledged && desktopMeasurementCancelRetired(launch, "latency-cancel.json") {
				return
			}
			if desktopMeasurementNativeClosed(launch) {
				*owner.failed = true
				return // The exact native close follows Latency worker/socket drain.
			}
			// Once acknowledged, let the native owner retire a late retry. Do
			// not recreate it while waiting, or delete another owner's input.
			if !acknowledged {
				_ = writeDesktopLatencyCleanupCancel(launch, request)
			}
			<-tick.C
		}
	}()
	if err := writeDesktopLatencyRequestContext(ctx, launch, "latency-request.json", request); err != nil {
		*owner.failed = true
		return result, err
	}
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	for {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		if err := operation.snapshot.currentContext(ctx, a); err != nil {
			return result, err
		}
		record, err := readDesktopLatencyRecordContext(ctx, launch)
		if err != nil {
			return result, err
		}
		if record.Generation == request.Generation {
			if record.desktopLatencyNativeRequest != request {
				return result, errors.New("native Latency request was replaced")
			}
			operation.update(record.Status)
			if record.Status.Complete && record.Status.Drained {
				drained = true
				if err := validateDesktopLatencyResults(launch, record.Status); err != nil {
					return result, err
				}
				return record.Status, operation.snapshot.currentContext(ctx, a)
			}
		} else if record.Generation+1 != request.Generation {
			return result, errors.New("native Latency generation changed")
		}
		select {
		case <-ctx.Done():
			return result, ctx.Err()
		case <-tick.C:
		}
	}
}
