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
	SessionID             string `json:"session_id"`
	ProfileID             string `json:"profile_id"`
	ProfileToken          string `json:"profile_token"`
	SourceSHA256          string `json:"source_sha256"`
	ConfigSHA256          string `json:"config_sha256"`
	GenerationSHA256      string `json:"generation_sha256"`
	SelectedCaptureJSON   string `json:"selected_capture,omitempty"`
	PairedPrefixNodes     int    `json:"paired_prefix_nodes,omitempty"`
	LocalRolesJSON        string `json:"local_roles_json,omitempty"`
	ExtendedLocalNodes    int    `json:"extended_local_nodes,omitempty"`
	ExtendedOriginalNodes int    `json:"extended_original_nodes,omitempty"`
}
type desktopOrderedLatencyNode struct {
	extended    *mobilemultihop.NodeChain
	config      string
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
	if chain.execution != nil {
		view, err = captureDesktopSelectedLatency(ctx, identity)
		return identity, view, err
	}
	if !chain.hasPolicy() || chain.preparation != nil || chain.execution != nil || !identity.GraphOK || identity.Graph.Execution != "local" {
		return identity, view, errors.New("ordered fifty requires the original retained Local source")
	}
	// captureSpeedLabIdentityContext has just validated this exact live native
	// owner. Read the complete policy and its original pointer together once;
	// repeating the entire native observation before any intervening I/O makes
	// a complete eight-node inventory exceed the unchanged caller deadline.
	_, meta, input, err := chain.readLaunchPolicy()
	if err != nil {
		return identity, view, err
	}
	if input != chain.input {
		return identity, view, errors.New("ordered fifty changed its exact original launch input")
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
	if err := ctx.Err(); err != nil {
		return identity, view, err
	}
	view = desktopOrderedLatencyView{Schema: 1, desktopOrderedLatencyRequest: desktopOrderedLatencyRequest{Capture: desktopOrderedLatencyCapture{SessionID: identity.SessionID, ProfileID: identity.RouterID, ProfileToken: identity.ProfileToken, SourceSHA256: meta.OriginalSourceSHA256, ConfigSHA256: meta.ConfigSHA256, GenerationSHA256: hex.EncodeToString(hash[:])}}, Status: hopmeasure.Status{Stage: "idle", Complete: true, Drained: true, Results: []hopmeasure.Result{}}}
	view.Nodes = nodes
	if nodes[0].extended != nil {
		view.Capture.ExtendedLocalNodes = len(nodes)
		view.Capture.PairedPrefixNodes = nodes[0].extended.ExtendedMixedLocalPacketCount()
		if nodes[0].extended.HasPairedStreamInterior() {
			view.Capture.LocalRolesJSON = nodes[0].extended.ExtendedLocalRolesJSON()
			view.Capture.PairedPrefixNodes = 0
			if _, err := desktopOrderedLocalRoles(view.Capture.LocalRolesJSON, len(nodes)); err != nil {
				return identity, desktopOrderedLatencyView{}, err
			}
		}
	}
	return identity, view, nil
}

// Only the validated, sealed policy decides whether a prefix is a private node
// or one of the original imported public members. A position or mutable UI label does
// not grant a different endpoint, timing budget or measurement meaning.
func desktopOrderedLatencyInventory(selection multihopSelection, meta mobilemultihop.DesktopNodeChainMetadata) ([]desktopOrderedLatencyNode, error) {
	count := len(selection.Nodes)
	var extended *mobilemultihop.NodeChain
	if count > mobilemultihop.NodeChainMaximumNodes {
		if selection.Native == nil || selection.Native.chain == nil || selection.Native.chain.chain == nil {
			return nil, errors.New("long ordered latency has no original Local source")
		}
		extended = selection.Native.chain.chain
		if extended.ExtendedLocalNodeCount() != count || extended.SourceSHA256() != meta.OriginalSourceSHA256 ||
			!reflect.DeepEqual(extended.ProofInventory(), meta.Prefixes) || !desktopOrderedDigest.MatchString(meta.ConfigSHA256) {
			return nil, errors.New("long ordered latency lost its original Local proof inventory")
		}
	}
	if count < 2 || len(meta.Prefixes) != count {
		return nil, errors.New("ordered fifty lost its complete captured inventory")
	}
	nodes := make([]desktopOrderedLatencyNode, 0, count)
	seen := map[string]bool{}
	for position, proof := range meta.Prefixes {
		id := selection.Nodes[position].Profile.ID
		if proof.Position != position || proof.ProfileID != id || !validProfileID(id) || seen[id] || extended != nil && proof.Mode != selection.Nodes[position].Mode {
			return nil, errors.New("ordered fifty changed its captured node or position")
		}
		seen[id] = true
		capturedKind := proof.Kind
		if capturedKind == "" {
			capturedKind = "private-node"
		}
		expectedKind := "private-node"
		if selection.Nodes[position].Profile.NodeKind == "external" {
			expectedKind = "public-path"
		}
		if capturedKind != expectedKind {
			return nil, errors.New("ordered fifty changed its captured private or imported source")
		}
		role, kind, label, metric, _ := desktopOrderedLatencyMeaning(position, count, capturedKind)
		if kind == "" {
			return nil, errors.New("ordered fifty changed its captured node kind")
		}
		node := desktopOrderedLatencyNode{NodeID: id, Position: position, Kind: kind, Role: role, Label: label, Measurement: metric}
		if extended != nil {
			node.extended, node.config = extended, meta.ConfigSHA256
		}
		nodes = append(nodes, node)
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

// The server compares this public envelope with the independently retained live
// capture before starting, polling or cancelling any measurement.
func (c desktopOrderedLatencyCapture) admitsPosition(position int) bool {
	if c.LocalRolesJSON != "" {
		if c.PairedPrefixNodes != 0 || c.SelectedCaptureJSON != "" || c.ExtendedOriginalNodes != 0 {
			return false
		}
		if _, err := desktopOrderedLocalRoles(c.LocalRolesJSON, c.ExtendedLocalNodes); err != nil {
			return false
		}
	}
	if c.PairedPrefixNodes != 0 && (c.ExtendedLocalNodes <= mobilemultihop.NodeChainMaximumNodes || c.SelectedCaptureJSON != "" || c.ExtendedOriginalNodes != 0 || c.PairedPrefixNodes < 1 || c.PairedPrefixNodes > c.ExtendedLocalNodes-2) {
		return false
	}
	if c.ExtendedOriginalNodes != 0 {
		return c.ExtendedLocalNodes == 0 && c.SelectedCaptureJSON != "" && c.ExtendedOriginalNodes > mobilemultihop.NodeChainMaximumNodes &&
			c.ExtendedOriginalNodes <= mobilemultihop.NodeChainExtendedLocalMaximumNodes && position >= 0 && position < c.ExtendedOriginalNodes
	}
	if c.ExtendedLocalNodes == 0 {
		return position >= 0 && position < mobilemultihop.NodeChainMaximumNodes
	}
	return c.SelectedCaptureJSON == "" && c.ExtendedLocalNodes > mobilemultihop.NodeChainMaximumNodes &&
		c.ExtendedLocalNodes <= mobilemultihop.NodeChainExtendedLocalMaximumNodes && position >= 0 && position < c.ExtendedLocalNodes
}
func readDesktopOrderedLatencyRequest(w http.ResponseWriter, r *http.Request) (desktopOrderedLatencyRequest, error) {
	var request desktopOrderedLatencyRequest
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, desktopSelectedExtendedCaptureLimit))
	if err != nil || decodePrivateControlJSONBounded(raw, &request, desktopSelectedExtendedCaptureLimit) != nil || !desktopMTURequestPattern.MatchString(request.Request) || request.Position < 0 || !request.Capture.admitsPosition(request.Position) || !validProfileID(request.NodeID) || !desktopOrderedSessionID.MatchString(request.Capture.SessionID) || !validProfileID(request.Capture.ProfileID) || request.Capture.ProfileToken == "" || !desktopOrderedDigest.MatchString(request.Capture.SourceSHA256) || !desktopOrderedDigest.MatchString(request.Capture.ConfigSHA256) || !desktopOrderedDigest.MatchString(request.Capture.GenerationSHA256) {
		return request, errors.New("exact ordered capture, node, position and fresh request_id are required")
	}
	if err := validateDesktopSelectedLatencyCaptureBinding(request.Capture); err != nil {
		return request, err
	}
	if request.Capture.SelectedCaptureJSON == "" && len(raw) > 4096 {
		return request, errors.New("ordinary ordered capture exceeds its original request bound")
	}
	if len(raw) > desktopSelectedCaptureBound(request.Capture.ExtendedOriginalNodes, 16384) {
		return request, errors.New("selected ordered capture exceeds its original source bound")
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
		history, err := readDesktopOrderedLatencyViewHistory(a, view)
		if err != nil {
			http.Error(w, "ordered history could not be read safely", 500)
			return
		}
		view.History = history
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
	var selectedResult desktopSelectedLatencyResult
	selected := op.request.Capture.SelectedCaptureJSON != ""
	if err == nil {
		err = op.current(ctx, a)
	}
	if err == nil {
		op.mu.Lock()
		op.status.Stage = "measuring fifty HTTP responses"
		op.mu.Unlock()
		if selected {
			selectedResult, err = exchangeDesktopSelectedLatencyOperation(ctx, launch, func(call context.Context) error { return op.current(call, a) }, op.request)
		} else {
			target := &desktopOrderedLatencyTarget{NodeID: op.request.NodeID, Position: op.request.Position, Request: op.request.Request}
			result, err = exchangeDesktopNodeChainMeasurementOperation(ctx, launch, func(call context.Context) error { return op.current(call, a) }, target)
		}
	}
	// Only a successfully published request can have original workers to join.
	issued := result.Request != "" || selectedResult.Request != ""
	if issued && errors.Is(err, errDesktopNodeChainMeasurementPending) {
		op.mu.Lock()
		op.status.Stage = "draining"
		op.status.Complete = true
		op.status.Drained = false
		op.status.Failure = "Waiting for original ordered native workers to join"
		op.mu.Unlock()
		if selected {
			waitDesktopSelectedLatencyDrain(launch, selectedResult.desktopSelectedLatencyRequest)
		} else {
			waitDesktopOrderedLatencyDrain(launch, result.desktopNodeChainMeasurementRequest)
		}
	}
	if err == nil {
		if selected {
			err = validateDesktopSelectedLatencyResult(op.request, op.node, selectedResult, time.Now())
		} else {
			err = validateDesktopOrderedLatencyResult(op.request, op.node, result, time.Now())
		}
	}
	saved, status := result.Saved, result.Status
	if selected {
		saved, status = selectedResult.Saved, selectedResult.Status
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
		err = op.node.saveCapturedHistory(a, op.request.Capture, *saved, func() error {
			if op.invalid || slot.current != op || ctx.Err() != nil {
				return errors.New("ordered commit lost its original operation")
			}
			return op.current(ctx, a)
		})
	}
	if err == nil {
		op.status = cloneDesktopLatencyStatus(status)
		op.receipt = saved
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
	if request.Capture.SelectedCaptureJSON != "" || request.Capture.ExtendedOriginalNodes != 0 || result.Schema != 2 || result.Operation != "ordered-latency-50" || result.Bytes != 0 || result.NodeID != request.NodeID || result.Position != request.Position || result.Request != request.Request || result.Saved == nil {
		return bad
	}
	saved := *result.Saved
	limit := node.receiptLimit(saved)
	if node.extended != nil && request.Capture.ExtendedLocalNodes != limit || node.extended == nil && request.Capture.ExtendedLocalNodes != 0 {
		return bad
	}
	if err := validateDesktopOrderedReceiptBound(saved, now, limit); err != nil {
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

// A long receipt is authorized only by the independently retained native
// Local source and the exact desktop configuration used for this measurement.
func (node desktopOrderedLatencyNode) receiptLimit(r hopmeasure.OrderedLatencyReceipt) int {
	if node.extended == nil {
		return mobilemultihop.NodeChainMaximumNodes
	}
	count := node.extended.ExtendedLocalNodeCount()
	if count <= mobilemultihop.NodeChainMaximumNodes || r.SourceSHA256 != node.extended.SourceSHA256() ||
		r.ConfigSHA256 != node.config || desktopOrderedReceiptCount(r) != count || r.Position < 0 || r.Position >= count || !desktopOrderedReceiptMatchesNode(r, node) {
		return 0
	}
	proof := node.extended.ProofInventory()[r.Position]
	if proof.ProfileID != r.NodeID || proof.Position != r.Position {
		return 0
	}
	return count
}

func (node desktopOrderedLatencyNode) saveCapturedHistory(a *app, capture desktopOrderedLatencyCapture, r hopmeasure.OrderedLatencyReceipt, current func() error) error {
	if node.extended == nil {
		return saveDesktopOrderedCapturedHistory(a, capture, r, current)
	}
	limit := node.receiptLimit(r)
	packets, roles := node.extended.ExtendedMixedLocalPacketCount(), ""
	if node.extended.HasPairedStreamInterior() {
		packets, roles = 0, node.extended.ExtendedLocalRolesJSON()
		if _, err := desktopOrderedLocalRoles(roles, limit); err != nil {
			return err
		}
	}
	if capture.SelectedCaptureJSON != "" || limit == 0 || capture.PairedPrefixNodes != packets || capture.LocalRolesJSON != roles || capture.ExtendedLocalNodes != limit || capture.SourceSHA256 != r.SourceSHA256 || capture.ConfigSHA256 != r.ConfigSHA256 || capture.GenerationSHA256 != r.GenerationSHA256 {
		return errors.New("ordered latency history changed its retained Local source")
	}
	return saveDesktopOrderedHistoryBound(a, r, current, limit)
}

// The canonical public envelope is comparable and contains no credentials.
// Native source ownership independently binds every role before publication;
// this parser alone never grants a graph or a measurement capability.
func desktopOrderedLocalRoles(raw string, count int) ([]string, error) {
	bad := errors.New("ordered Local roles changed their complete captured inventory")
	if count <= mobilemultihop.NodeChainMaximumNodes || count > mobilemultihop.NodeChainExtendedLocalMaximumNodes || len(raw) > 2048 {
		return nil, bad
	}
	var roles []string
	if json.Unmarshal([]byte(raw), &roles) != nil || len(roles) != count || roles[0] != "private-node" || roles[count-1] != "private-node" {
		return nil, bad
	}
	public, privateInterior := false, false
	for position, role := range roles {
		if role != "private-node" && role != "public-path" {
			return nil, bad
		}
		public = public || role == "public-path"
		privateInterior = privateInterior || position > 0 && position < count-1 && role == "private-node"
	}
	canonical, err := json.Marshal(roles)
	if err != nil || !public || !privateInterior || string(canonical) != raw {
		return nil, bad
	}
	return roles, nil
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
