package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"router-vpn/internal/mobilemtu"
	"time"
)

// A throughput preflight binds every prefix and the final to one already
// selected trial. Its token cannot be used for candidate handshakes.
func captureOrderedThroughputContext(ctx context.Context, a *app) (speedLabPathIdentity, string, int, error) {
	raw, _ := nativeMultihopOwners.Load(a)
	owner, _ := raw.(*nativeMultihopRuntime)
	if owner == nil || owner.execution == nil {
		return captureOrderedPerformanceContext(ctx, a)
	}
	ctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	identity, _, err := captureSpeedLabIdentityContext(ctx, a)
	if err != nil || identity.Ordered != owner {
		return identity, "", 0, errors.Join(err, errors.New("selected throughput lost the retained connected native route"))
	}
	publication, ready, _, nodes, err := readDesktopSelectedLatencyCapture(ctx, owner.launch)
	if err != nil {
		return identity, "", 0, err
	}
	token, err := orderedSelectedMeasurementCapture(identity, ready, publication.Selected, "routervpn-selected-throughput-v1")
	return identity, token, len(nodes), errors.Join(err, ctx.Err())
}

func measureDesktopSelectedThroughput(ctx context.Context, a *app, identity speedLabPathIdentity, expected string) ([]speedLabHopMeasurement, error) {
	launch := identity.Ordered.launch
	publication, ready, capture, nodes, err := readDesktopSelectedLatencyCapture(ctx, launch)
	if err != nil || len(nodes) < 2 || capture.Execution != identity.Graph.Execution {
		return nil, errors.Join(err, errors.New("selected throughput lost the complete original node inventory"))
	}
	token, err := orderedSelectedMeasurementCapture(identity, ready, publication.Selected, "routervpn-selected-throughput-v1")
	if err != nil || expected != "" && token != expected {
		return nil, errors.Join(err, errors.New("selected throughput changed since its route preflight"))
	}
	current := func(call context.Context) error {
		if err := validateSpeedLabIdentityContext(call, a, identity); err != nil {
			return err
		}
		live, latest, _, _, err := readDesktopSelectedLatencyCapture(call, launch)
		if err != nil || live.Selected != publication.Selected || !sameDesktopSelectedLatencyReady(ready, latest) {
			return errors.Join(err, errors.New("selected throughput changed its original proof or winner"))
		}
		return call.Err()
	}
	nonce, err := randomHex(16)
	if err != nil {
		return nil, err
	}
	last := nodes[len(nodes)-1]
	input := desktopOrderedLatencyRequest{Request: nonce, NodeID: last.NodeID, Position: last.Position,
		Capture: desktopOrderedLatencyCapture{SessionID: identity.SessionID, ProfileID: identity.RouterID, ProfileToken: identity.ProfileToken,
			SourceSHA256: capture.SourceSHA256, ConfigSHA256: capture.ConfigSHA256, GenerationSHA256: capture.GenerationSHA256,
			SelectedCaptureJSON: publication.Selected}}
	hold, err := beginDesktopNodeChainMeasurementHold(ctx, a, launch)
	if err != nil {
		return nil, err
	}
	result, err := exchangeDesktopSelectedMeasurementOperation(ctx, launch, current, input, 8<<20)
	if errors.Is(err, errDesktopNodeChainMeasurementPending) && result.Request != "" {
		// Return the caller's error promptly. Retain only this measurement's MTU
		// hold until the exact original child acknowledges joined retirement.
		go func() {
			waitDesktopSelectedThroughputDrain(launch, result.desktopSelectedLatencyRequest, result.throughputFile)
			hold(true)
		}()
		return nil, err
	}
	defer hold(true)
	if err != nil {
		return nil, err
	}
	if err := current(ctx); err != nil {
		return nil, err
	}
	return desktopNodeChainThroughputRows(result.Status, launch.chain.selection.Nodes, 8<<20, capture.Execution)
}

const desktopSelectedThroughputResultFile = "node-chain-execution-throughput-result.json"

type desktopThroughputResultFile struct {
	info os.FileInfo
	raw  []byte
}

func (f *desktopThroughputResultFile) read(ctx context.Context, launch *desktopNodeLaunch) ([]byte, error) {
	// The child's terminal link is provisional until it has consumed the
	// original request. Check on both sides of the read before pinning a receipt.
	absent := func() (bool, error) {
		_, err := launch.directoryRoot.Lstat(desktopSelectedLatencyRequestFile)
		if errors.Is(err, os.ErrNotExist) {
			return true, nil
		}
		return false, err
	}
	if ok, err := absent(); !ok || err != nil {
		return nil, err
	}
	raw, info, err := readDesktopSelectedCandidateFile(ctx, launch, desktopSelectedThroughputResultFile, 128<<10)
	if err != nil {
		return nil, err
	}
	if ok, err := absent(); !ok || err != nil {
		return nil, err
	}
	if f.info == nil {
		f.info, f.raw = info, bytes.Clone(raw)
	} else if !os.SameFile(f.info, info) || !bytes.Equal(f.raw, raw) {
		return nil, errors.New("original throughput result was replaced")
	}
	return raw, nil
}

func (f *desktopThroughputResultFile) retire(ctx context.Context, launch *desktopNodeLaunch) error {
	return retireDesktopSelectedCandidateCaptured(ctx, launch, desktopSelectedThroughputResultFile, f.raw, f.info)
}

func waitDesktopSelectedThroughputDrain(launch *desktopNodeLaunch, request desktopSelectedLatencyRequest, file *desktopThroughputResultFile) {
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
			raw, err := file.read(ctx, launch)
			result, decodeErr := decodeDesktopSelectedLatencyResult(raw)
			if err == nil && decodeErr == nil && reflect.DeepEqual(request, result.desktopSelectedLatencyRequest) &&
				result.Status.Request == request.Request && result.Status.Complete && result.Status.Drained &&
				retireDesktopSelectedLatencyCancel(ctx, launch, rawRequest) == nil && file.retire(ctx, launch) == nil {
				stopped = true
			}
		}
		cancel()
		if stopped {
			return
		}
		<-ticker.C
	}
}
