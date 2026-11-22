package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"time"

	"router-vpn/internal/hopmeasure"
	"router-vpn/internal/mobilemtu"
	"router-vpn/internal/mobilemultihop"
)

const desktopSelectedLatencyRequestFile = "node-chain-execution-measure-request.json"
const desktopSelectedLatencyCancelFile = "node-chain-execution-measure-cancel.json"
const desktopSelectedLatencyResultFile = "node-chain-execution-measure-result.json"

type desktopSelectedLatencyRequest struct {
	Schema     int                                                 `json:"schema"`
	Operation  string                                              `json:"operation"`
	Request    string                                              `json:"request_id"`
	Generation uint64                                              `json:"generation"`
	Deadline   int64                                               `json:"deadline_at"`
	Path       string                                              `json:"path_id"`
	NodeID     string                                              `json:"node_id"`
	Position   int                                                 `json:"position"`
	Capture    mobilemultihop.DesktopNodeChainExecutionReadyRecord `json:"capture"`
	Selected   string                                              `json:"selected_capture"`
}

type desktopSelectedLatencyResult struct {
	desktopSelectedLatencyRequest
	Saved       *hopmeasure.OrderedLatencyReceipt `json:"saved,omitempty"`
	CompletedAt int64                             `json:"completed_at"`
	Status      hopmeasure.Status                 `json:"status"`
}

func decodeDesktopSelectedLatencyResult(raw []byte) (desktopSelectedLatencyResult, error) {
	var result desktopSelectedLatencyResult
	var fields map[string]json.RawMessage
	bad := errors.New("selected native measurement returned an incomplete private record")
	if decodePrivateControlJSONBounded(raw, &result, 128<<10) != nil || json.Unmarshal(raw, &fields) != nil || len(fields) < 12 || len(fields) > 13 {
		return result, bad
	}
	for _, name := range []string{"schema", "operation", "request_id", "generation", "deadline_at", "path_id", "node_id", "position", "capture", "selected_capture", "completed_at", "status"} {
		if value, exists := fields[name]; !exists || bytes.Equal(value, []byte("null")) {
			return result, bad
		}
	}
	if result.Schema != 1 || result.Operation != "selected-latency-50" || !desktopMTURequestPattern.MatchString(result.Request) ||
		result.Generation == 0 || result.Deadline <= 0 || !desktopMTUPathPattern.MatchString(result.Path) {
		return result, bad
	}
	_, nodes, err := decodeDesktopSelectedLatencyCapture(result.Selected)
	if err != nil || result.Position < 0 || result.Position >= len(nodes) || nodes[result.Position].NodeID != result.NodeID {
		return result, bad
	}
	return result, nil
}

// The selected mailbox never dispatches through the ordinary Local controller.
// The original selected facade, native reader, source files and complete capture
// are pinned for this request; no preparation, winner or runtime is recreated.
func exchangeDesktopSelectedLatencyOperation(parent context.Context, launch *desktopNodeLaunch, current func(context.Context) error, selected desktopOrderedLatencyRequest) (desktopSelectedLatencyResult, error) {
	var empty desktopSelectedLatencyResult
	if parent == nil || parent.Err() != nil || current == nil || desktopNodeChainLaunchExecution(launch) == nil ||
		selected.Capture.SelectedCaptureJSON == "" || validateDesktopSelectedLatencyCaptureBinding(selected.Capture) != nil {
		return empty, errors.New("selected measurement requires its exact retained execution owner")
	}
	ctx, cancel := context.WithTimeout(parent, hopmeasure.RequestTimeout)
	defer cancel()
	chain := launch.chain
	if err := mobilemtu.LockContext(ctx, &chain.measurementMu); err != nil {
		return empty, err
	}
	defer chain.measurementMu.Unlock()
	if err := desktopSelectedCandidateMeasurementIdle(ctx, launch); err != nil {
		return empty, err
	}
	if err := current(ctx); err != nil {
		return empty, err
	}
	publication, ready, _, nodes, err := readDesktopSelectedLatencyCapture(ctx, launch)
	if err != nil || publication.Selected != selected.Capture.SelectedCaptureJSON || selected.Position < 0 ||
		selected.Position >= len(nodes) || nodes[selected.Position].NodeID != selected.NodeID || !desktopMTURequestPattern.MatchString(selected.Request) {
		return empty, errors.Join(err, errors.New("selected measurement changed its original node or facade"))
	}
	live, err := readDesktopNodeMTUContext(ctx, launch)
	if err != nil || live.Active || live.Failure != "" || live.Reader != ready.Reader || live.Session != ready.Identity.SessionID ||
		live.Config != ready.PreparationConfigSHA256 || live.Interface != ready.InterfaceName || live.Index != int(ready.InterfaceIndex) || live.MTU != ready.MTU {
		return empty, errors.Join(err, errors.New("selected measurement cannot borrow another MTU reader"))
	}
	names := []string{"sing-box.json", "node-chain-execution-source.json", "node-chain-execution-latency-capture.json"}
	infos := make([]os.FileInfo, len(names))
	bodies := make([][]byte, len(names))
	defer func() {
		for _, raw := range bodies {
			clear(raw)
		}
	}()
	for index, name := range names {
		infos[index], err = launch.directoryRoot.Lstat(name)
		if err != nil {
			return empty, err
		}
		bodies[index], err = readDesktopRuntimeFileContext(ctx, launch, name, mobilemultihop.NodeChainInputLimit)
		if err != nil {
			return empty, err
		}
	}
	e := chain.execution
	if string(bodies[0]) != e.preparation.Config() || string(bodies[1]) != e.preparation.Source() {
		return empty, errors.New("selected measurement source differs from its original preparation")
	}
	check := func(call context.Context) error {
		if err := current(call); err != nil {
			return err
		}
		for index, name := range names {
			info, err := launch.directoryRoot.Lstat(name)
			if err != nil || !os.SameFile(info, infos[index]) {
				return errors.New("selected measurement original private inode changed")
			}
			raw, err := readDesktopRuntimeFileContext(call, launch, name, mobilemultihop.NodeChainInputLimit)
			unchanged := err == nil && bytes.Equal(raw, bodies[index])
			clear(raw)
			if !unchanged {
				return errors.New("selected measurement original private bytes changed")
			}
		}
		after, err := readDesktopNodeMTUContext(call, launch)
		if err != nil || after.Session != live.Session || after.Config != live.Config || after.Path != live.Path ||
			after.Reader != live.Reader || after.Interface != live.Interface || after.Index != live.Index || after.MTU != live.MTU || after.Active || after.Failure != "" {
			return errors.Join(err, errors.New("selected measurement TUN reader changed"))
		}
		return call.Err()
	}
	if chain.measurementGeneration == ^uint64(0) {
		return empty, errors.New("selected measurement generation exhausted")
	}
	deadline, _ := ctx.Deadline()
	request := desktopSelectedLatencyRequest{Schema: 1, Operation: "selected-latency-50", Request: selected.Request,
		Generation: chain.measurementGeneration + 1, Deadline: deadline.UnixMilli(), Path: live.Path,
		NodeID: selected.NodeID, Position: selected.Position, Capture: ready, Selected: publication.Selected}
	empty.desktopSelectedLatencyRequest = request
	raw, err := json.Marshal(request)
	if err != nil || len(raw) > 16384 {
		return empty, errors.New("selected measurement request exceeds its private bound")
	}
	if err := check(ctx); err != nil {
		return empty, err
	}
	started := time.Now().UnixMilli()
	if err := publishDesktopNodeChainMeasurement(ctx, launch, desktopSelectedLatencyRequestFile, raw); err != nil {
		return empty, err
	}
	chain.measurementGeneration = request.Generation
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	read := func(call context.Context) (*desktopSelectedLatencyResult, error) {
		body, err := readDesktopRuntimeFileContext(call, launch, desktopSelectedLatencyResultFile, 128<<10)
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		result, err := decodeDesktopSelectedLatencyResult(body)
		if err != nil {
			return nil, err
		}
		if result.Request != request.Request {
			if result.Request == chain.measurementLast {
				return nil, nil
			}
			return nil, errors.New("selected measurement returned another request")
		}
		if !reflect.DeepEqual(result.desktopSelectedLatencyRequest, request) || result.CompletedAt < started-1 ||
			result.CompletedAt > time.Now().Add(time.Second).UnixMilli() || result.Status.Request != request.Request || !result.Status.Complete || !result.Status.Drained {
			return nil, errors.New("selected measurement result changed its complete original owner")
		}
		if _, err := readDesktopRuntimeFileContext(call, launch, desktopSelectedLatencyRequestFile, 16384); !errors.Is(err, os.ErrNotExist) {
			if err != nil {
				return nil, err
			}
			return nil, nil
		}
		return &result, nil
	}
	drain := func(cause error) (desktopSelectedLatencyResult, error) {
		joined, stop := context.WithTimeout(context.Background(), 7*time.Second)
		defer stop()
		if result, err := read(joined); err == nil && result != nil {
			chain.measurementLast = request.Request
			return empty, cause
		}
		if err := publishDesktopNodeChainMeasurement(joined, launch, desktopSelectedLatencyCancelFile, raw); err != nil {
			return empty, errors.Join(cause, err, errDesktopNodeChainMeasurementPending)
		}
		for {
			if result, err := read(joined); err == nil && result != nil {
				chain.measurementLast = request.Request
				return empty, errors.Join(cause, retireDesktopSelectedLatencyCancel(joined, launch, raw))
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
				return empty, errors.New("selected native measurement failed or expired")
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

func retireDesktopSelectedLatencyCancel(ctx context.Context, launch *desktopNodeLaunch, expected []byte) error {
	if err := mobilemtu.LockContext(ctx, &launch.workspaceMu); err != nil {
		return err
	}
	defer launch.workspaceMu.Unlock()
	if err := desktopExternalDirectoryCurrent(launch); err != nil {
		return err
	}
	before, err := launch.directoryRoot.Lstat(desktopSelectedLatencyCancelFile)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	raw, readErr := readDesktopRuntimeSnapshot(launch.directoryRoot, desktopSelectedLatencyCancelFile, 16384)
	after, statErr := launch.directoryRoot.Lstat(desktopSelectedLatencyCancelFile)
	if err != nil || readErr != nil || statErr != nil || !os.SameFile(before, after) || !bytes.Equal(raw, expected) {
		return errors.New("selected cancellation was replaced before original drain")
	}
	return launch.directoryRoot.Remove(desktopSelectedLatencyCancelFile)
}

func validateDesktopSelectedLatencyResult(request desktopOrderedLatencyRequest, node desktopOrderedLatencyNode, result desktopSelectedLatencyResult, now time.Time) error {
	bad := errors.New("selected native saved receipt differs from its original request")
	if result.Schema != 1 || result.Operation != "selected-latency-50" || result.Request != request.Request ||
		result.NodeID != request.NodeID || result.Position != request.Position || result.Selected != request.Capture.SelectedCaptureJSON || result.Saved == nil {
		return bad
	}
	saved := *result.Saved
	if err := validateDesktopSelectedLatencyReceipt(result.Selected, saved, now); err != nil {
		return err
	}
	if !desktopOrderedReceiptMatchesNode(saved, node) || saved.NodeID != request.NodeID || saved.Position != request.Position ||
		saved.Request != request.Request || saved.MeasuredAt > result.CompletedAt || saved.MeasuredAt > result.Deadline {
		return bad
	}
	status := result.Status
	if status.Request != request.Request || !status.Complete || !status.Drained || status.Stage != "complete" || status.Failure != "" || len(status.Results) != 1 || !reflect.DeepEqual(status.Results[0], saved.Result) {
		return bad
	}
	return validateDesktopSelectedLatencyCaptureBinding(request.Capture)
}

func waitDesktopSelectedLatencyDrain(launch *desktopNodeLaunch, request desktopSelectedLatencyRequest) {
	rawRequest, _ := json.Marshal(request)
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		stopped, _ := readDesktopNodeStoppedContext(ctx, launch)
		if !stopped && mobilemtu.LockContext(ctx, &launch.chain.mu) == nil {
			stopped = launch.chain.measurementOwner == nil
			launch.chain.mu.Unlock()
		}
		if !stopped {
			raw, err := readDesktopRuntimeFileContext(ctx, launch, desktopSelectedLatencyResultFile, 128<<10)
			result, decodeErr := decodeDesktopSelectedLatencyResult(raw)
			if err == nil && decodeErr == nil && reflect.DeepEqual(result.desktopSelectedLatencyRequest, request) && result.Status.Request == request.Request && result.Status.Complete && result.Status.Drained {
				_, err = readDesktopRuntimeFileContext(ctx, launch, desktopSelectedLatencyRequestFile, 16384)
				if errors.Is(err, os.ErrNotExist) {
					stopped = retireDesktopSelectedLatencyCancel(ctx, launch, rawRequest) == nil
				}
			}
		}
		cancel()
		if stopped {
			return
		}
		<-ticker.C
	}
}
