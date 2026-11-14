package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"time"

	"router-vpn/internal/hopmeasure"
	"router-vpn/internal/mobilemtu"
	"router-vpn/internal/mobilemultihop"
)

type desktopNodeChainMeasurementRequest struct {
	Operation  string                                     `json:"operation,omitempty"`
	NodeID     string                                     `json:"node_id,omitempty"`
	Position   int                                        `json:"position,omitempty"`
	Schema     int                                        `json:"schema"`
	Request    string                                     `json:"request_id"`
	Generation uint64                                     `json:"generation"`
	Deadline   int64                                      `json:"deadline_at"`
	Bytes      int                                        `json:"bytes"`
	Path       string                                     `json:"path_id"`
	Capture    mobilemultihop.DesktopNodeChainReadyRecord `json:"capture"`
}
type desktopNodeChainMeasurementResult struct {
	desktopNodeChainMeasurementRequest
	Saved       *hopmeasure.OrderedLatencyReceipt `json:"saved,omitempty"`
	CompletedAt int64                             `json:"completed_at"`
	Status      hopmeasure.Status                 `json:"status"`
}

var errDesktopNodeChainMeasurementPending = errors.New("ordered native measurement drain remains owned")

type desktopNodeChainMeasurementHold struct{ release func() }

func measureSpeedLabOrderedHops(ctx context.Context, a *app, identity speedLabPathIdentity) ([]speedLabHopMeasurement, error) {
	if identity.Ordered == nil || identity.Ordered.launch == nil || identity.Ordered.launch.chain == nil {
		return nil, errors.New("ordered measurement has no retained original launch")
	}
	launch := identity.Ordered.launch
	finishHold, err := beginDesktopNodeChainMeasurementHold(ctx, a, launch)
	if err != nil {
		return nil, err
	}
	status, err := exchangeDesktopNodeChainMeasurement(ctx, launch, func(call context.Context) error { return validateSpeedLabIdentityContext(call, a, identity) })
	finishHold(!errors.Is(err, errDesktopNodeChainMeasurementPending))
	if err != nil {
		return nil, err
	}
	if err := validateSpeedLabIdentityContext(ctx, a, identity); err != nil {
		return nil, err
	}
	return desktopNodeChainMeasurementRows(status, launch.chain.selection.Nodes, 8<<20)
}

func beginDesktopNodeChainMeasurementHold(ctx context.Context, a *app, launch *desktopNodeLaunch) (func(bool), error) {
	if a == nil || launch == nil || launch.chain == nil {
		return nil, errors.New("ordered measurement hold lost its retained launch")
	}
	release, err := a.holdCapturedMTU(ctx)
	if err != nil {
		return nil, err
	}
	if err := mobilemtu.LockContext(ctx, &launch.chain.mu); err != nil {
		release()
		return nil, err
	}
	if launch.chain.measurementRelease != nil {
		launch.chain.mu.Unlock()
		release()
		return nil, errDesktopNodeChainMeasurementPending
	}
	owner := &desktopNodeChainMeasurementHold{release: release}
	launch.chain.measurementRelease = release
	launch.chain.measurementOwner = owner
	launch.chain.mu.Unlock()
	return func(joined bool) {
		if !joined {
			return
		}
		launch.chain.mu.Lock()
		if launch.chain.measurementOwner != owner {
			launch.chain.mu.Unlock()
			return
		}
		launch.chain.measurementRelease = nil
		launch.chain.measurementOwner = nil
		launch.chain.mu.Unlock()
		release()
	}, nil
}

func desktopNodeChainMeasurementRows(status hopmeasure.Status, members []desktopNodeChainMember, size int) ([]speedLabHopMeasurement, error) {
	bad := errors.New("ordered measurement did not prove every captured node prefix")
	if !status.Complete || !status.Drained || status.Stage != "complete" || status.Failure != "" || len(members) < 2 || len(members) > 8 || len(status.Results) != len(members) {
		return nil, bad
	}
	rows := make([]speedLabHopMeasurement, len(members))
	finite := func(v float64) bool { return !math.IsNaN(v) && !math.IsInf(v, 0) && v > 0 }
	transfer := func(t *hopmeasure.Transfer) bool {
		return t != nil && t.Bytes == int64(size) && finite(t.Seconds) && t.Seconds <= 90 && finite(t.Mbps) && math.Abs(t.Mbps-float64(t.Bytes)*8/t.Seconds/1e6) < 0.0011
	}
	for i, r := range status.Results {
		role := "intermediate"
		if i == 0 {
			role = "entry"
		}
		if i == len(members)-1 {
			role = "exit"
		}
		p := members[i].Profile
		kind := "private-node"
		imported := desktopNodeChainImported(p, members[i].Mode) || desktopNodeChainSOCKSMiddle(p, members[i].Mode) || desktopNodeChainCONNECTMiddle(p, members[i].Mode)
		if imported {
			if len(members) != 3 || i != 1 {
				return nil, bad
			}
			kind = "public-path"
		}
		if p.NodeKind == "external" && !imported {
			return nil, bad
		}
		if r.ID != p.ID || r.Role != role || r.Kind != kind || !r.Ready || r.Failure != "" || r.Idle == nil || r.Benchmark != nil || r.Response != nil || r.Idle.Samples != 6 || math.IsNaN(r.Idle.Jitter) || math.IsInf(r.Idle.Jitter, 0) || r.Idle.Jitter < 0 || r.Idle.Min > r.Idle.Median || r.Idle.Median > r.Idle.P90 || r.Idle.P90 > r.Idle.Max || r.Idle.Average < r.Idle.Min || r.Idle.Average > r.Idle.Max || !finite(r.Idle.Min) || !finite(r.Idle.Median) || !finite(r.Idle.Average) || !finite(r.Idle.P90) || !finite(r.Idle.Max) || !transfer(r.Download) || !transfer(r.Upload) {
			return nil, bad
		}
		label := fmt.Sprintf("Cumulative path through node %d of %d", i+1, len(members))
		latencyProof := label + " through the retained authenticated native prefix"
		speedProof := label + " independently transferred exact authenticated bytes"
		if imported {
			label += " to the public benchmark"
			latencyProof = label + " through the original imported SS2022 transport"
			speedProof = label + " transferred exact public benchmark bytes"
		}
		measured := time.Now()
		rows[i] = speedLabHopMeasurement{Role: role, RouterID: p.ID, Name: p.Name, LatencyLabel: label + " HTTP response", SpeedLabel: label + " transfer",
			Latency: &connectionLatencyResult{Connected: true, Mode: "multihop", RouterID: p.ID, Name: p.Name, Samples: r.Idle.Samples, MinMs: r.Idle.Min, MedianMs: r.Idle.Median, AverageMs: r.Idle.Average, P90Ms: r.Idle.P90, MaxMs: r.Idle.Max, MeasuredAt: measured, Proof: latencyProof},
			Speed:   &routedSpeedResult{RouterID: p.ID, Name: p.Name, Bytes: int64(size), DownloadMbps: r.Download.Mbps, UploadMbps: r.Upload.Mbps, DownloadMs: r.Download.Seconds * 1000, UploadMs: r.Upload.Seconds * 1000, MeasuredAt: measured, Proof: speedProof}}
	}
	return rows, nil
}

// Only the captured child dials the private APIs. This exchange never creates a
// proxy, adopts another process, or reconstructs a member from mutable selection.
func exchangeDesktopNodeChainMeasurement(parent context.Context, launch *desktopNodeLaunch, current func(context.Context) error) (hopmeasure.Status, error) {
	result, err := exchangeDesktopNodeChainMeasurementOperation(parent, launch, current, nil)
	return result.Status, err
}

type desktopOrderedLatencyTarget struct {
	NodeID   string
	Position int
	Request  string
}

func exchangeDesktopNodeChainMeasurementOperation(parent context.Context, launch *desktopNodeLaunch, current func(context.Context) error, target *desktopOrderedLatencyTarget) (desktopNodeChainMeasurementResult, error) {
	var empty desktopNodeChainMeasurementResult
	if parent == nil || parent.Err() != nil || launch == nil || launch.chain == nil || current == nil {
		return empty, errors.New("ordered measurement requires its original caller and launch")
	}
	ctx, cancel := context.WithTimeout(parent, hopmeasure.RequestTimeout)
	defer cancel()
	chain := launch.chain
	if err := mobilemtu.LockContext(ctx, &chain.measurementMu); err != nil {
		return empty, err
	}
	defer chain.measurementMu.Unlock()
	if err := current(ctx); err != nil {
		return empty, err
	}
	if err := validateDesktopNodeChainLaunch(ctx, launch); err != nil {
		return empty, errors.Join(err, ctx.Err())
	}
	live, err := readDesktopNodeMTUContext(ctx, launch)
	if err != nil {
		return empty, err
	}
	if live.Active || live.Failure != "" {
		return empty, errors.New("ordered measurement cannot borrow an MTU transaction")
	}
	if err := mobilemtu.LockContext(ctx, &chain.mu); err != nil {
		return empty, err
	}
	if chain.ready == nil {
		chain.mu.Unlock()
		return empty, errors.New("ordered measurement lost its proved chain")
	}
	capture := *chain.ready
	chain.mu.Unlock()
	capture, err = readDesktopNodeChainReadyContext(ctx, launch, capture.TransferSHA256, time.UnixMilli(capture.ObservedAt), false, live)
	if err != nil {
		return empty, err
	}
	configFile, err := launch.directoryRoot.Lstat("sing-box.json")
	if err != nil {
		return empty, err
	}
	sourceFile, err := launch.directoryRoot.Lstat(chain.sourceName())
	if err != nil {
		return empty, err
	}
	check := func(call context.Context) error {
		if err := current(call); err != nil {
			return err
		}
		configNow, configErr := launch.directoryRoot.Lstat("sing-box.json")
		sourceNow, sourceErr := launch.directoryRoot.Lstat(chain.sourceName())
		if configErr != nil || sourceErr != nil || !os.SameFile(configFile, configNow) || !os.SameFile(sourceFile, sourceNow) {
			return errors.New("ordered measurement source inode changed")
		}
		configRaw, err := readDesktopRuntimeFileContext(call, launch, "sing-box.json", mobilemultihop.NodeChainInputLimit)
		if err != nil || string(configRaw) != chain.policyConfig() {
			return errors.Join(err, call.Err(), errors.New("ordered measurement config changed"))
		}
		raw, err := readDesktopRuntimeFileContext(call, launch, chain.sourceName(), mobilemultihop.NodeChainInputLimit)
		if err != nil || string(raw) != chain.input {
			return errors.New("ordered measurement source changed")
		}
		after, err := readDesktopNodeMTUContext(call, launch)
		if err != nil {
			return err
		}
		if after.Session != live.Session || after.Config != live.Config || after.Path != live.Path || after.Reader != live.Reader || after.Interface != live.Interface || after.Index != live.Index || after.MTU != live.MTU || after.Active || after.Failure != "" {
			return errors.New("ordered measurement TUN reader changed")
		}
		return call.Err()
	}
	if chain.measurementGeneration == ^uint64(0) {
		return empty, errors.New("ordered measurement generation exhausted")
	}
	nonce, err := randomHex(16)
	if err != nil {
		return empty, err
	}
	deadline, _ := ctx.Deadline()
	request := desktopNodeChainMeasurementRequest{Schema: 1, Request: nonce, Generation: chain.measurementGeneration + 1, Deadline: deadline.UnixMilli(), Bytes: 8 << 20, Path: live.Path, Capture: capture}
	if target != nil {
		if !chain.hasPolicy() || chain.policy != nil || target.Position < 0 || target.Position >= len(chain.selection.Nodes) || chain.selection.Nodes[target.Position].Profile.ID != target.NodeID {
			return empty, errors.New("ordered fifty requires its exact typed member")
		}
		request.Schema, request.Operation, request.Bytes = 2, "ordered-latency-50", 0
		request.NodeID, request.Position = target.NodeID, target.Position
		if !desktopMTURequestPattern.MatchString(target.Request) {
			return empty, errors.New("ordered fifty requires a fresh request identity")
		}
		request.Request = target.Request
	}
	empty.desktopNodeChainMeasurementRequest = request
	raw, _ := json.Marshal(request)
	started := time.Now().UnixMilli()
	if err := check(ctx); err != nil {
		return empty, err
	}
	if err := publishDesktopNodeChainMeasurement(ctx, launch, "node-chain-measure-request.json", raw); err != nil {
		return empty, err
	}
	chain.measurementGeneration = request.Generation
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	read := func(call context.Context) (*desktopNodeChainMeasurementResult, error) {
		raw, err := readDesktopRuntimeFileContext(call, launch, "node-chain-measure-result.json", 128<<10)
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		var result desktopNodeChainMeasurementResult
		if decodeRelayControlJSON(raw, &result) != nil || target == nil && !desktopNodeChainOrdinaryResultShape(raw) {
			return nil, errors.New("ordered measurement malformed result")
		}
		if result.Request != request.Request {
			if result.Request == chain.measurementLast {
				return nil, nil
			}
			return nil, errors.New("ordered measurement foreign result")
		}
		if result.desktopNodeChainMeasurementRequest != request || result.CompletedAt < started-1 || result.CompletedAt > time.Now().Add(time.Second).UnixMilli() || result.Status.Request != request.Request || !result.Status.Complete || !result.Status.Drained {
			return nil, errors.New("ordered measurement result changed its captured owner")
		}
		if _, err := readDesktopRuntimeFileContext(call, launch, "node-chain-measure-request.json", 16384); !errors.Is(err, os.ErrNotExist) {
			if err != nil {
				return nil, err
			}
			return nil, nil
		}
		return &result, nil
	}
	drain := func(cause error) (desktopNodeChainMeasurementResult, error) {
		joined, stop := context.WithTimeout(context.Background(), 7*time.Second)
		defer stop()
		if result, err := read(joined); err == nil && result != nil {
			chain.measurementLast = request.Request
			return empty, cause
		}
		if err := publishDesktopNodeChainMeasurement(joined, launch, "node-chain-measure-cancel.json", raw); err != nil {
			return empty, errors.Join(cause, err, errDesktopNodeChainMeasurementPending)
		}
		for {
			if result, err := read(joined); err == nil && result != nil {
				chain.measurementLast = request.Request
				return empty, errors.Join(cause, retireDesktopNodeChainMeasurementCancel(joined, launch, raw))
			}
			if stopped, _ := readDesktopNodeStoppedContext(joined, launch); stopped {
				return empty, cause
			}
			select {
			case <-joined.Done():
				return empty, errors.Join(cause, errDesktopNodeChainMeasurementPending)
			case <-ticker.C:
			}
		}
	}
	for {
		if err := check(ctx); err != nil {
			return drain(errors.Join(err, ctx.Err()))
		}
		result, err := read(ctx)
		if err != nil {
			return drain(errors.Join(err, ctx.Err()))
		}
		if result != nil {
			chain.measurementLast = request.Request
			if result.CompletedAt > request.Deadline || result.Status.Failure != "" {
				return empty, errors.New("ordered native measurement failed or expired")
			}
			if err := check(ctx); err != nil {
				return empty, err
			}
			return *result, nil
		}
		select {
		case <-ctx.Done():
			return drain(ctx.Err())
		case <-ticker.C:
		}
	}
}

func publishDesktopNodeChainMeasurement(ctx context.Context, launch *desktopNodeLaunch, name string, raw []byte) error {
	return publishDesktopNodeChainMeasurementWithWriter(ctx, launch, name, raw, func(file *os.File, body []byte) error {
		_, err := file.Write(body)
		return err
	})
}

// Complete and sync a private inode before making its public mailbox name
// visible. Link is atomic and refuses an existing destination on all desktop
// platforms; Rename could overwrite a replacement owner's request.
func publishDesktopNodeChainMeasurementWithWriter(ctx context.Context, launch *desktopNodeLaunch, name string, raw []byte, write func(*os.File, []byte) error) error {
	limit := desktopNodeChainMailboxLimit(name)
	if launch == nil || launch.directoryRoot == nil || limit == 0 || len(raw) == 0 || len(raw) > limit || write == nil {
		return errors.New("invalid ordered measurement message")
	}
	if err := mobilemtu.LockContext(ctx, &launch.workspaceMu); err != nil {
		return err
	}
	defer launch.workspaceMu.Unlock()
	if err := desktopExternalDirectoryCurrent(launch); err != nil {
		return err
	}
	temporary := "." + name + ".pending"
	file, err := launch.directoryRoot.OpenFile(temporary, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	info, statErr := file.Stat()
	defer func() {
		_ = file.Close()
		if actual, err := launch.directoryRoot.Lstat(temporary); err == nil && info != nil && os.SameFile(info, actual) {
			_ = launch.directoryRoot.Remove(temporary)
		}
	}()
	if statErr != nil {
		return statErr
	}
	if err := write(file, raw); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	actual, err := launch.directoryRoot.Lstat(temporary)
	if err != nil || !os.SameFile(info, actual) || actual.Size() != int64(len(raw)) {
		return errors.New("ordered measurement private message changed before publication")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := desktopExternalDirectoryCurrent(launch); err != nil {
		return err
	}
	// After Link the native consumer may immediately consume the public name.
	// The caller owns cancellation/drain even if its context ends right now.
	return launch.directoryRoot.Link(temporary, name)
}

func desktopNodeChainMailboxLimit(name string) int {
	switch name {
	case "node-candidate-prefix-request.json", "node-candidate-prefix-cancel.json", "node-chain-measure-request.json", "node-chain-measure-cancel.json", "node-chain-candidate-request.json", "node-chain-candidate-cancel.json":
		return 16384
	case "node-chain-candidate-source.json":
		return mobilemultihop.NodeChainInputLimit
	case "node-candidate-prefix-live.json", "node-chain-candidate-live.json":
		return 4096
	}
	return 0
}

// Cancellation can race an already completed native query. Remove only this
// exact caller's late cancel after its result/request has joined.
func retireDesktopNodeChainMeasurementCancel(ctx context.Context, launch *desktopNodeLaunch, expected []byte) error {
	if err := mobilemtu.LockContext(ctx, &launch.workspaceMu); err != nil {
		return err
	}
	defer launch.workspaceMu.Unlock()
	if err := desktopExternalDirectoryCurrent(launch); err != nil {
		return err
	}
	before, err := launch.directoryRoot.Lstat("node-chain-measure-cancel.json")
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	actual, readErr := readDesktopRuntimeSnapshot(launch.directoryRoot, "node-chain-measure-cancel.json", 16384)
	after, statErr := launch.directoryRoot.Lstat("node-chain-measure-cancel.json")
	if err != nil || readErr != nil || statErr != nil || !os.SameFile(before, after) || string(actual) != string(expected) {
		return errors.New("ordered measurement cancellation file changed before drain")
	}
	return launch.directoryRoot.Remove("node-chain-measure-cancel.json")
}

func desktopNodeChainOrdinaryResultShape(raw []byte) bool {
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil {
		return false
	}
	for _, name := range []string{"operation", "node_id", "position", "saved"} {
		if _, exists := fields[name]; exists {
			return false
		}
	}
	return true
}
