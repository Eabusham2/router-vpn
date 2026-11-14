package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"reflect"
	"sync"
	"time"

	"router-vpn/internal/hopmeasure"
	"router-vpn/internal/mobilemtu"
	"router-vpn/internal/mobilemultihop"
)

type desktopOrderedLatencyCapture struct {
	SessionID        string `json:"session_id"`
	ProfileID        string `json:"profile_id"`
	ProfileToken     string `json:"profile_token"`
	SourceSHA256     string `json:"source_sha256"`
	ConfigSHA256     string `json:"config_sha256"`
	GenerationSHA256 string `json:"generation_sha256"`
}
type desktopOrderedLatencyNode struct {
	NodeID      string `json:"node_id"`
	Position    int    `json:"position"`
	Kind        string `json:"kind"`
	Role        string `json:"role"`
	Label       string `json:"label"`
	Measurement string `json:"measurement"`
}
type desktopOrderedLatencyRequest struct {
	Capture  desktopOrderedLatencyCapture `json:"capture"`
	NodeID   string                       `json:"node_id"`
	Position int                          `json:"position"`
	Request  string                       `json:"request_id"`
}
type desktopOrderedLatencyView struct {
	Schema int `json:"schema"`
	desktopOrderedLatencyRequest
	Nodes   []desktopOrderedLatencyNode        `json:"nodes,omitempty"`
	History []hopmeasure.OrderedLatencyReceipt `json:"history,omitempty"`
	Status  hopmeasure.Status                  `json:"status"`
	Receipt *hopmeasure.OrderedLatencyReceipt  `json:"receipt,omitempty"`
}
type desktopOrderedLatencySlot struct {
	mu        sync.Mutex
	known     map[desktopOrderedLatencyCapture][]desktopOrderedLatencyNode
	capture   desktopOrderedLatencyCapture
	current   *desktopOrderedLatencyOperation
	used      map[string]bool
	cancelled map[string]desktopOrderedLatencyRequest
}
type desktopOrderedLatencyOperation struct {
	mu       sync.Mutex
	request  desktopOrderedLatencyRequest
	node     desktopOrderedLatencyNode
	identity speedLabPathIdentity
	status   hopmeasure.Status
	receipt  *hopmeasure.OrderedLatencyReceipt
	cancel   context.CancelFunc
	done     chan struct{}
	invalid  bool
}

func (a *app) desktopOrderedLatencyFor() *desktopOrderedLatencySlot {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.orderedLatencyMeasurements == nil {
		a.orderedLatencyMeasurements = &desktopOrderedLatencySlot{known: map[desktopOrderedLatencyCapture][]desktopOrderedLatencyNode{}, used: map[string]bool{}, cancelled: map[string]desktopOrderedLatencyRequest{}}
	}
	return a.orderedLatencyMeasurements
}
func captureDesktopOrderedLatency(ctx context.Context, a *app) (speedLabPathIdentity, desktopOrderedLatencyView, error) {
	var view desktopOrderedLatencyView
	identity, _, err := captureSpeedLabIdentityContext(ctx, a)
	if err != nil {
		return identity, view, err
	}
	if speedLabTemporaryPersistenceSuppressed(a) || identity.Ordered == nil || identity.Ordered.launch == nil || identity.Ordered.launch.chain == nil {
		return identity, view, errors.New("ordered fifty requires the selected retained typed connection")
	}
	chain := identity.Ordered.launch.chain
	if !chain.hasPolicy() || chain.preparation != nil || chain.execution != nil || !chain.originalPolicyCurrent() || !identity.GraphOK || identity.Graph.Execution != "local" || len(chain.selection.Nodes) < 2 || len(chain.selection.Nodes) > 8 {
		return identity, view, errors.New("ordered fifty requires the original retained Local source")
	}
	if err := validateSpeedLabIdentityContext(ctx, a, identity); err != nil {
		return identity, view, err
	}
	_, meta, _, err := chain.readPolicy()
	if err != nil {
		return identity, view, err
	}
	nodes, err := desktopOrderedLatencyInventory(chain.selection, meta)
	if err != nil {
		return identity, view, err
	}
	if err := mobilemtu.LockContext(ctx, &chain.mu); err != nil {
		return identity, view, err
	}
	if chain.ready == nil {
		chain.mu.Unlock()
		return identity, view, errors.New("ordered fifty lost its native ready capture")
	}
	ready := *chain.ready
	chain.mu.Unlock()
	raw, err := json.Marshal(ready.Identity)
	if err != nil {
		return identity, view, err
	}
	hash := sha256.Sum256(raw)
	view = desktopOrderedLatencyView{Schema: 1, desktopOrderedLatencyRequest: desktopOrderedLatencyRequest{Capture: desktopOrderedLatencyCapture{SessionID: identity.SessionID, ProfileID: identity.RouterID, ProfileToken: identity.ProfileToken, SourceSHA256: meta.OriginalSourceSHA256, ConfigSHA256: meta.ConfigSHA256, GenerationSHA256: hex.EncodeToString(hash[:])}}, Status: hopmeasure.Status{Stage: "idle", Complete: true, Drained: true, Results: []hopmeasure.Result{}}}
	view.Nodes = nodes
	return identity, view, nil
}

// Only the validated, sealed policy decides whether a prefix is a private node
// or the supported imported public middle. A position or mutable UI label does
// not grant a different endpoint, timing budget or measurement meaning.
func desktopOrderedLatencyInventory(selection multihopSelection, meta mobilemultihop.DesktopNodeChainMetadata) ([]desktopOrderedLatencyNode, error) {
	count := len(selection.Nodes)
	if count < 2 || count > 8 || len(meta.Prefixes) != count {
		return nil, errors.New("ordered fifty lost its complete captured inventory")
	}
	nodes := make([]desktopOrderedLatencyNode, 0, count)
	seen := map[string]bool{}
	for position, proof := range meta.Prefixes {
		id := selection.Nodes[position].Profile.ID
		if proof.Position != position || proof.ProfileID != id || !validProfileID(id) || seen[id] {
			return nil, errors.New("ordered fifty changed its captured node or position")
		}
		seen[id] = true
		capturedKind := proof.Kind
		if capturedKind == "" {
			capturedKind = "private-node"
		}
		role, kind, label, metric, _ := desktopOrderedLatencyMeaning(position, count, capturedKind)
		if kind == "" {
			return nil, errors.New("ordered fifty changed its captured node kind")
		}
		nodes = append(nodes, desktopOrderedLatencyNode{NodeID: id, Position: position, Kind: kind, Role: role, Label: label, Measurement: metric})
	}
	return nodes, nil
}
func (o *desktopOrderedLatencyOperation) current(ctx context.Context, a *app) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err := validateSpeedLabIdentityContext(ctx, a, o.identity); err != nil {
		return err
	}
	_, view, err := captureDesktopOrderedLatency(ctx, a)
	if err != nil || view.Capture != o.request.Capture || o.request.Position < 0 || o.request.Position >= len(view.Nodes) || view.Nodes[o.request.Position] != o.node || o.node.NodeID != o.request.NodeID {
		return errors.Join(err, errors.New("ordered benchmark captured source or generation changed"))
	}
	return nil
}
func readDesktopOrderedLatencyRequest(w http.ResponseWriter, r *http.Request) (desktopOrderedLatencyRequest, error) {
	var request desktopOrderedLatencyRequest
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 4096))
	if err != nil || decodeRelayControlJSON(raw, &request) != nil || !desktopMTURequestPattern.MatchString(request.Request) || request.Position < 0 || request.Position > 7 || !validProfileID(request.NodeID) || !desktopOrderedSessionID.MatchString(request.Capture.SessionID) || !validProfileID(request.Capture.ProfileID) || request.Capture.ProfileToken == "" || !desktopOrderedDigest.MatchString(request.Capture.SourceSHA256) || !desktopOrderedDigest.MatchString(request.Capture.ConfigSHA256) || !desktopOrderedDigest.MatchString(request.Capture.GenerationSHA256) {
		return request, errors.New("exact ordered capture, node, position and fresh request_id are required")
	}
	return request, nil
}
func desktopOrderedCancelledView(request desktopOrderedLatencyRequest) desktopOrderedLatencyView {
	return desktopOrderedLatencyView{Schema: 1, desktopOrderedLatencyRequest: request, Status: hopmeasure.Status{Request: request.Request, Stage: "cancelled", Complete: true, Drained: true, Failure: "Ordered benchmark cancelled before native work", Results: []hopmeasure.Result{}}}
}
func (o *desktopOrderedLatencyOperation) view() desktopOrderedLatencyView {
	o.mu.Lock()
	defer o.mu.Unlock()
	view := desktopOrderedLatencyView{Schema: 1, desktopOrderedLatencyRequest: o.request, Status: cloneDesktopLatencyStatus(o.status), Receipt: o.receipt}
	if view.Status.Complete && view.Status.Drained {
		select {
		case <-o.done:
		default:
			view.Status.Stage, view.Status.Complete, view.Status.Drained = "finishing", false, false
			view.Status.Results = []hopmeasure.Result{}
			view.Receipt = nil
		}
	}
	return view
}
func (a *app) desktopOrderedLatencyMeasurement(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		request := r.URL.Query().Get("request_id")
		if request != "" {
			if !desktopMTURequestPattern.MatchString(request) {
				http.Error(w, "invalid ordered request identity", 400)
				return
			}
			slot := a.desktopOrderedLatencyFor()
			slot.mu.Lock()
			operation := slot.current
			cancelled, ok := slot.cancelled[request]
			slot.mu.Unlock()
			if operation != nil && operation.request.Request == request {
				writeDesktopLatencyJSON(w, 200, operation.view())
			} else if ok {
				writeDesktopLatencyJSON(w, 200, desktopOrderedCancelledView(cancelled))
			} else {
				http.Error(w, "ordered request replaced or unknown", 409)
			}
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 4*time.Second)
		defer cancel()
		_, view, err := captureDesktopOrderedLatency(ctx, a)
		if err != nil {
			http.Error(w, err.Error(), 409)
			return
		}
		history, err := readDesktopOrderedHistory(a)
		if err != nil {
			http.Error(w, "ordered history could not be read safely", 500)
			return
		}
		for _, saved := range history.Receipts {
			if saved.SourceSHA256 == view.Capture.SourceSHA256 && saved.ConfigSHA256 == view.Capture.ConfigSHA256 && saved.Position >= 0 && saved.Position < len(view.Nodes) && desktopOrderedReceiptMatchesNode(saved, view.Nodes[saved.Position]) {
				view.History = append(view.History, saved)
			}
		}
		slot := a.desktopOrderedLatencyFor()
		slot.mu.Lock()
		err = slot.remember(view)
		slot.mu.Unlock()
		if err != nil {
			http.Error(w, err.Error(), 409)
			return
		}
		writeDesktopLatencyJSON(w, 200, view)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "GET or POST only", 405)
		return
	}
	request, err := readDesktopOrderedLatencyRequest(w, r)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	release, err := a.beginNodeBoundOperation()
	if err != nil {
		http.Error(w, err.Error(), 409)
		return
	}
	defer release()
	finish, err := beginSpeedLabRun(a)
	if err != nil {
		http.Error(w, err.Error(), 409)
		return
	}
	transferred := false
	defer func() {
		if !transferred {
			finish()
		}
	}()
	ctx, stop := context.WithTimeout(r.Context(), 4*time.Second)
	defer stop()
	identity, view, err := captureDesktopOrderedLatency(ctx, a)
	if err != nil || view.Capture != request.Capture || request.Position >= len(view.Nodes) || view.Nodes[request.Position].NodeID != request.NodeID {
		http.Error(w, "ordered source, generation or member changed before Retest", 409)
		return
	}
	slot := a.desktopOrderedLatencyFor()
	slot.mu.Lock()
	if err := slot.remember(view); err != nil {
		slot.mu.Unlock()
		http.Error(w, err.Error(), 409)
		return
	}
	if old := slot.current; old != nil {
		select {
		case <-old.done:
		default:
			slot.mu.Unlock()
			http.Error(w, "original ordered workers are still draining", 409)
			return
		}
	}
	if prior, exists := slot.cancelled[request.Request]; exists && prior == request {
		slot.mu.Unlock()
		http.Error(w, "ordered request cancelled before admission", 409)
		return
	}
	if slot.capture != request.Capture {
		slot.capture = request.Capture
		slot.used = map[string]bool{}
		slot.cancelled = map[string]desktopOrderedLatencyRequest{}
	}
	if slot.used[request.Request] || len(slot.used) >= 256 || len(slot.cancelled) >= 256 {
		slot.mu.Unlock()
		http.Error(w, "ordered request reused, cancelled or session budget exhausted", 409)
		return
	}
	work, cancel := context.WithTimeout(context.Background(), hopmeasure.RequestTimeout)
	op := &desktopOrderedLatencyOperation{request: request, node: view.Nodes[request.Position], identity: identity, cancel: cancel, done: make(chan struct{}), status: hopmeasure.Status{Request: request.Request, Stage: "preparing", Results: []hopmeasure.Result{}}}
	slot.used[request.Request], slot.current = true, op
	slot.mu.Unlock()
	transferred = true
	go a.runDesktopOrderedLatency(work, slot, op, finish)
	writeDesktopLatencyJSON(w, 202, op.view())
}
func (a *app) cancelDesktopOrderedLatencyMeasurement(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", 405)
		return
	}
	request, err := readDesktopOrderedLatencyRequest(w, r)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	slot := a.desktopOrderedLatencyFor()
	slot.mu.Lock()
	operation := slot.current
	if operation != nil && operation.request.Request == request.Request {
		if operation.request != request {
			slot.mu.Unlock()
			http.Error(w, "ordered cancellation belongs to another capture", 409)
			return
		}
		slot.mu.Unlock()
		operation.mu.Lock()
		if operation.receipt == nil {
			operation.invalid = true
			operation.cancel()
		}
		operation.mu.Unlock()
		writeDesktopLatencyJSON(w, 202, operation.view())
		return
	}
	if prior, ok := slot.cancelled[request.Request]; ok {
		slot.mu.Unlock()
		if prior != request {
			http.Error(w, "ordered cancellation identity changed", 409)
			return
		}
		writeDesktopLatencyJSON(w, 200, desktopOrderedCancelledView(prior))
		return
	}
	slot.mu.Unlock()
	slot.mu.Lock()
	nodes, known := slot.known[request.Capture]
	slot.mu.Unlock()
	if !known {
		ctx, cancel := context.WithTimeout(r.Context(), 4*time.Second)
		_, view, captureErr := captureDesktopOrderedLatency(ctx, a)
		cancel()
		if captureErr != nil || view.Capture != request.Capture {
			http.Error(w, "queued cancellation requires its original captured path", 409)
			return
		}
		slot.mu.Lock()
		err = slot.remember(view)
		nodes = slot.known[request.Capture]
		slot.mu.Unlock()
		if err != nil {
			http.Error(w, err.Error(), 409)
			return
		}
	}
	if request.Position >= len(nodes) || nodes[request.Position].NodeID != request.NodeID {
		http.Error(w, "queued cancellation changed original member", 409)
		return
	}
	slot.mu.Lock()
	defer slot.mu.Unlock()
	// Start may have admitted this exact request during capture. Cancel that
	// original operation, never a request-string match on a replacement.
	if op := slot.current; op != nil && op.request.Request == request.Request {
		if op.request != request {
			http.Error(w, "ordered cancellation changed owner", 409)
			return
		}
		op.mu.Lock()
		if op.receipt == nil {
			op.invalid = true
			op.cancel()
		}
		op.mu.Unlock()
		writeDesktopLatencyJSON(w, 202, op.view())
		return
	}
	if len(slot.cancelled) >= 256 {
		http.Error(w, "ordered cancellation request budget exhausted", 409)
		return
	}
	if slot.capture == request.Capture {
		slot.used[request.Request] = true
	}
	slot.cancelled[request.Request] = request
	writeDesktopLatencyJSON(w, 200, desktopOrderedCancelledView(request))
}
func (a *app) runDesktopOrderedLatency(ctx context.Context, slot *desktopOrderedLatencySlot, op *desktopOrderedLatencyOperation, finish func()) {
	defer close(op.done)
	defer op.cancel()
	defer finish()
	launch := op.identity.Ordered.launch
	hold, err := beginDesktopNodeChainMeasurementHold(ctx, a, launch)
	if err == nil {
		defer func() { hold(true) }()
	}
	var result desktopNodeChainMeasurementResult
	if err == nil {
		err = op.current(ctx, a)
	}
	if err == nil {
		op.mu.Lock()
		op.status.Stage = "measuring fifty HTTP responses"
		op.mu.Unlock()
		target := &desktopOrderedLatencyTarget{NodeID: op.request.NodeID, Position: op.request.Position, Request: op.request.Request}
		result, err = exchangeDesktopNodeChainMeasurementOperation(ctx, launch, func(call context.Context) error { return op.current(call, a) }, target)
	}
	if errors.Is(err, errDesktopNodeChainMeasurementPending) {
		op.mu.Lock()
		op.status.Stage = "draining"
		op.status.Complete = true
		op.status.Drained = false
		op.status.Failure = "Waiting for original ordered native workers to join"
		op.mu.Unlock()
		waitDesktopOrderedLatencyDrain(launch, result.desktopNodeChainMeasurementRequest)
	}
	if err == nil {
		err = validateDesktopOrderedLatencyResult(op.request, op.node, result, time.Now())
	}
	if err == nil {
		err = op.current(ctx, a)
	}
	// Only this short durable transaction blocks connection/settings mutation.
	// Network work, cancellation and native drainage never hold operationMu.
	var release func()
	if err == nil {
		release, err = a.beginNodeBoundOperation()
		if release != nil {
			defer release()
		}
	}
	slot.mu.Lock()
	defer slot.mu.Unlock()
	op.mu.Lock()
	defer op.mu.Unlock()
	if err == nil && (op.invalid || slot.current != op || slot.capture != op.request.Capture) {
		err = errors.New("ordered operation cancelled or replaced before durable adoption")
	}
	if err == nil {
		err = saveDesktopOrderedHistory(a, *result.Saved, func() error {
			if op.invalid || slot.current != op || ctx.Err() != nil {
				return errors.New("ordered commit lost its original operation")
			}
			return op.current(ctx, a)
		})
	}
	if err == nil {
		op.status = cloneDesktopLatencyStatus(result.Status)
		op.receipt = result.Saved
		return
	}
	stage := "failed"
	if op.invalid || errors.Is(err, context.Canceled) {
		stage = "cancelled"
	}
	op.status = hopmeasure.Status{Request: op.request.Request, Stage: stage, Complete: true, Drained: true, Failure: "Ordered benchmark or durable adoption failed; no committed receipt is available", Results: []hopmeasure.Result{}}
}
func validateDesktopOrderedLatencyResult(request desktopOrderedLatencyRequest, node desktopOrderedLatencyNode, result desktopNodeChainMeasurementResult, now time.Time) error {
	bad := errors.New("ordered native saved receipt differs from its original request")
	if result.Schema != 2 || result.Operation != "ordered-latency-50" || result.Bytes != 0 || result.NodeID != request.NodeID || result.Position != request.Position || result.Request != request.Request || result.Saved == nil {
		return bad
	}
	saved := *result.Saved
	if err := validateDesktopOrderedReceipt(saved, now); err != nil {
		return err
	}
	if !desktopOrderedReceiptMatchesNode(saved, node) {
		return bad
	}
	c := request.Capture
	if saved.SourceSHA256 != c.SourceSHA256 || saved.ConfigSHA256 != c.ConfigSHA256 || saved.GenerationSHA256 != c.GenerationSHA256 || saved.NodeID != request.NodeID || saved.Position != request.Position || saved.Request != request.Request || saved.MeasuredAt > result.CompletedAt || saved.MeasuredAt > result.Deadline {
		return bad
	}
	status := result.Status
	if status.Request != request.Request || !status.Complete || !status.Drained || status.Stage != "complete" || status.Failure != "" || len(status.Results) != 1 || !reflect.DeepEqual(status.Results[0], saved.Result) {
		return bad
	}
	return nil
}

// A failed bounded drain does not authorize releasing its Speed Lab/MTU lease.
// Continue only retirement observation; no new samples or late commits occur.
func waitDesktopOrderedLatencyDrain(launch *desktopNodeLaunch, request desktopNodeChainMeasurementRequest) {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		stopped, _ := readDesktopNodeStoppedContext(ctx, launch)
		if !stopped {
			if mobilemtu.LockContext(ctx, &launch.chain.mu) == nil {
				stopped = launch.chain.measurementOwner == nil
				launch.chain.mu.Unlock()
			}
		}
		if !stopped {
			raw, err := readDesktopRuntimeFileContext(ctx, launch, "node-chain-measure-result.json", 128<<10)
			var result desktopNodeChainMeasurementResult
			if err == nil && decodeRelayControlJSON(raw, &result) == nil && result.desktopNodeChainMeasurementRequest == request && result.Status.Request == request.Request && result.Status.Complete && result.Status.Drained {
				_, err = readDesktopRuntimeFileContext(ctx, launch, "node-chain-measure-request.json", 16384)
				if errors.Is(err, os.ErrNotExist) {
					stopped = retireDesktopNodeChainMeasurementCancel(ctx, launch, mustDesktopOrderedRequestJSON(request)) == nil
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
func mustDesktopOrderedRequestJSON(request desktopNodeChainMeasurementRequest) []byte {
	raw, _ := json.Marshal(request)
	return raw
}

func (slot *desktopOrderedLatencySlot) remember(view desktopOrderedLatencyView) error {
	if slot.known == nil {
		slot.known = map[desktopOrderedLatencyCapture][]desktopOrderedLatencyNode{}
	}
	if _, exists := slot.known[view.Capture]; !exists && len(slot.known) >= 128 {
		return errors.New("ordered captured-session budget exhausted")
	}
	slot.known[view.Capture] = append([]desktopOrderedLatencyNode(nil), view.Nodes...)
	return nil
}
